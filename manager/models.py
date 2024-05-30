import json

from django.db import models
from django.utils.translation import gettext_lazy as _


class Device(models.Model):

    name = models.CharField(max_length=100, verbose_name=_('Device name'))
    ipv4 = models.GenericIPAddressField(protocol='IPv4', verbose_name=_('IPv4 address'))
    created_date = models.DateTimeField(auto_now_add=True, verbose_name=_('Created datetime'))

    class Meta:
        verbose_name = 'IoT Device'
        verbose_name_plural = 'IoT Devices'

    def __str__(self):
        return f'{self.ipv4} - {self.name}'

    def analyze_history(self):
        result = {
            'name': self.name,
            'address': self.ipv4,
            'created_date': self.created_date,
        }

        device_history = DeviceAnalyzeHistory.objects.filter(device_id=self.pk)
        stats = {
            'prediction_score_sum': 0,
            'prediction_score_count': 0,
            'payload_count': 0,
            'packet_length': 0,
            'analysis_count': 0,
        }
        for history in device_history:  # type: DeviceAnalyzeHistory
            history.analyze_history(stats)

        if stats['prediction_score_count'] > 0:
            device_stat = {
                'prediction_score_avg': round(
                    stats['prediction_score_sum'] / stats['prediction_score_count'], 3
                ),
                'payload_count': stats['payload_count'],
            }
        else:
            device_stat = {
                'prediction_score_avg': 'Undef.',
                'payload_count': 0
            }

        device_stat['packet_length'] = stats['packet_length']
        device_stat['analysis_count'] = stats['analysis_count']
        result.update(device_stat)
        return result


class DeviceAnalyzeHistory(models.Model):

    device = models.ForeignKey(Device, on_delete=models.CASCADE, verbose_name=_('Device'))
    result = models.TextField(verbose_name=_('Analysis result'))
    created_date = models.DateTimeField(auto_now_add=True, verbose_name=_('Create datetime'))

    class Meta:
        verbose_name = 'IoT Network Analysis'
        verbose_name_plural = 'IoT Network Analysis'

    def __str__(self):
        return f'Analysis: {self.device}'

    def analyze_history(self, stats: dict):
        result = self.result
        stats['analysis_count'] += 1

        try:
            result_json = json.loads(result)
            stats['prediction_score_sum'] += result_json.get('prediction_score', 0)
            stats['prediction_score_count'] += 1
            stats['payload_count'] = sum(
                1 for i in result_json.get('analysis', list()) if i.get('has_file_payload')
            )
            stats['packet_length'] += sum(
                i.get('packet_length', 0) for i in result_json.get('analysis', list())
            ) // 10 ** 6
        except:  # noqa
            pass

        return stats
