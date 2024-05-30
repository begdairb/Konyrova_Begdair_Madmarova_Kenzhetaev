from django import forms

from . import models


class DeviceForm(forms.ModelForm):

    class Meta:
        model = models.Device
        fields = '__all__'


class AnalysisForm(forms.Form):

    pcap_file = forms.FileField()

    class Meta:
        fields = '__all__'
