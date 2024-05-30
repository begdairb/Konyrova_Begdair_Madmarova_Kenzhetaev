from typing import Optional, List

import pandas as pd

from core import DatasetType
from core import utils
from core.ml.dataset import DataSetMixin


class Predictor(DataSetMixin):

    def __init__(self, dataset_type: DatasetType, output_feature: Optional[str] = None):
        super().__init__(dataset_type=dataset_type, output_feature=output_feature)
        self._model = utils.load_model(self._dataset_type)

    def predict(self, prediction_input: List[dict]):

        trained_dataset_keys = list(self._data.keys())
        trained_dataset_keys.remove(self._output_feature)

        data = []
        for row in prediction_input:
            data.append(pd.Series(row, index=trained_dataset_keys))

        predictions = self._model.predict(data)

        return predictions
