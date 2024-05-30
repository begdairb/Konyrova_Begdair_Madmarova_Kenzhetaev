import json
import traceback
from copy import deepcopy

from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.shortcuts import redirect
from django.urls import reverse
from django.views.generic.base import TemplateView

from core import DatasetType
from core.analyzer.network import NetworkAnalyzer
from core.ml.predictor import Predictor
from manager.forms import DeviceForm, AnalysisForm
from manager.models import Device, DeviceAnalyzeHistory


class IndexPage(TemplateView):
    template_name = 'manager/index_page.html'


class LoginPage(TemplateView):
    template_name = 'manager/login_page.html'

    def post(self, request, *args, **kwargs):
        username = request.POST.get('username')
        password = request.POST.get('password')

        if not (username and password):
            messages.error(request, 'Username and password are required!')
            return redirect(reverse('manager:login_page'))

        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect(reverse('manager:dashboard_page'))

        messages.error(request, 'User authentication failed. Try again!')
        return redirect(reverse('manager:login_page'))


def logout_action(request):
    logout(request)
    return redirect(reverse('manager:index_page'))


class DashboardPage(TemplateView):
    template_name = 'manager/dashboard_page.html'
    form = DeviceForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)

        devices = {}
        for device in Device.objects.all():
            device_stat = device.analyze_history()
            devices[device.pk] = device_stat

        ctx['devices'] = devices

        return ctx

    def post(self, request, *args, **kwargs):
        form = self.form(request.POST)

        redirect_url = 'manager:dashboard_page'
        redirect_kwargs = None
        if form.is_valid():
            device = form.save()
            redirect_url = 'manager:device_page'
            redirect_kwargs = dict(pk=device.pk)
        else:
            messages.error(request, 'Invalid form. Check for errors')

        return redirect(reverse(redirect_url, kwargs=redirect_kwargs))


class DevicePage(TemplateView):
    template_name = 'manager/device_page.html'
    form = AnalysisForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)

        history = DeviceAnalyzeHistory.objects.filter(
            device_id=kwargs['pk']
        ).order_by('-pk').select_related('device')

        history_data = {}
        overall_stats = {
            'prediction_score_sum': 0,
            'prediction_score_count': 0,
            'payload_count': 0,
            'packet_length': 0,
            'analysis_count': 0,
            'prediction_score_avg': 0,
        }

        for history_obj in history:  # type: DeviceAnalyzeHistory
            history_obj_stat = deepcopy(overall_stats)
            history_obj_stat = history_obj.analyze_history(history_obj_stat)
            history_obj_stat.update(dict(
                created_date=history_obj.created_date,
                result=history_obj.result,
            ))

            prediction_score_avg = 'Undef.'
            if history_obj_stat.get('prediction_score_count') > 0:
                prediction_score_avg = round(
                    history_obj_stat.get('prediction_score_sum', 0) /
                    history_obj_stat.get('prediction_score_count'), 2
                )
            history_obj_stat['prediction_score_avg'] = prediction_score_avg

            history_data[history_obj.pk] = history_obj_stat

        for stat in history_data.values():
            for stat_key, stat_val in stat.items():
                if isinstance(stat_val, (int, float)):
                    overall_stats[stat_key] += stat_val

        if history:
            overall_stats['created_date'] = history.first().device.created_date

        ctx['history'] = history_data
        ctx['overall_stats'] = overall_stats
        return ctx

    def post(self, request, *args, **kwargs):

        form = self.form(request.POST, request.FILES)
        if form.is_valid():
            try:
                analyzer = NetworkAnalyzer()
                analysis = analyzer.analyze(form.cleaned_data['pcap_file'])

                predictor = Predictor(DatasetType.NETWORK, output_feature='is_malicious')
                prediction = list(predictor.predict(analysis))

                score = sum(prediction) / len(prediction)

                result = {
                    'analysis': analysis,
                    'prediction_score': score,
                }

                DeviceAnalyzeHistory.objects.create(
                    device_id=kwargs['pk'],
                    result=json.dumps(result)
                )

                messages.info(request, 'Analysis is ready to check')
            except:  # noqa
                traceback.print_exc()
                messages.error(request, 'Something went wrong in processing. Try again later!')
        else:
            messages.error(request, 'Form is invalid')

        return redirect(reverse('manager:device_page', kwargs=kwargs))
