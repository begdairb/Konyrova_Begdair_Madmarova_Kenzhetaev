import abc
from typing import List


class BaseAnalyzer:

    @abc.abstractmethod
    def analyze(self, *args, **kwargs):
        raise NotImplementedError


def dump_analysis(results: List[dict], dataset_path: str, is_malicious: int = 1, append: bool = False):
    features = set()
    for result in results:
        features.update(set(result.keys()))

    features_sorted = sorted(list(features))
    mode = 'w' if not append else 'r+'
    with open(dataset_path, mode) as f:
        if not append:
            f.write(';'.join(features_sorted) + ';is_malicious' + '\n')

        for result in results:
            result_row = ';'.join([str(result.get(feature, '')) for feature in features_sorted])
            f.write(result_row + f';{is_malicious}' + '\n')
