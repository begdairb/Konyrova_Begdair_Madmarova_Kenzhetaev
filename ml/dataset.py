from typing import Optional

import pandas as pd

from core import DatasetType


class DataSetMixin:

    DEFAULT_OUTPUT_FEATURE = 'not_identified_feature'

    def __init__(self, dataset_type: DatasetType, output_feature: Optional[str] = None, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if not output_feature:
            output_feature = self.DEFAULT_OUTPUT_FEATURE

        dataset_path = DatasetType.get_dataset_path(dataset_type)
        self._data = pd.read_csv(dataset_path, sep=';')
        self._output_feature = output_feature
        self._dataset_type = dataset_type
