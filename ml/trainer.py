from typing import Optional

from sklearn import tree
from sklearn import model_selection

from core import DatasetType
from core import utils
from core.ml.dataset import DataSetMixin


class Trainer(DataSetMixin):

    DEFAULT_OUTPUT_FEATURE = 'is_malware'

    def __init__(self, dataset_type: DatasetType, output_feature: Optional[str] = None):
        super().__init__(dataset_type=dataset_type, output_feature=output_feature)
        self._classifier = tree.DecisionTreeClassifier

    def train(self):
        x_input = self._data.drop(columns=[self._output_feature])
        y_output = self._data[self._output_feature]

        x_train, _, y_train, _ = model_selection.train_test_split(x_input, y_output, test_size=0.25)

        model = self._classifier()
        model.fit(x_train, y_train)

        utils.dump_model(model, self._dataset_type)
