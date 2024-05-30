from pathlib import Path

from sklearn.metrics import accuracy_score

from core import DatasetType
from core.analyzer import base, network
from core.ml.trainer import Trainer
from core.ml.predictor import Predictor


# Load datasets
base_path = Path() / 'core' / 'dataset' / 'network'

malicious_path = (base_path / 'malicious').resolve()
benign_path = (base_path / 'benign').resolve()

malicious_paths = []
for path in malicious_path.iterdir():
    malicious_paths.append(str(path.resolve().as_posix()))

benign_paths = []
for path in benign_path.iterdir():
    benign_paths.append(str(path.resolve().as_posix()))

# Analyze
analyzer = network.NetworkAnalyzer()

malicious_results = []
for path in malicious_paths:
    result = analyzer.analyze(path)
    malicious_results.extend(result)

benign_results = []
for path in benign_paths:
    print('path', path)
    try:
        result = analyzer.analyze(path)
        benign_results.extend(result)
    except Exception as exc:
        print('exc', exc)

# Dump
dataset_path = str(DatasetType.get_dataset_path(DatasetType.NETWORK).as_posix())
base.dump_analysis(malicious_results, dataset_path, is_malicious=1, append=False)

base.dump_analysis(benign_results, dataset_path, is_malicious=0, append=True)


# Train
trainer = Trainer(DatasetType.NETWORK, output_feature='is_malicious')
trainer.train()

# Predict
network_analyzer = network.NetworkAnalyzer()

pcap_file_path = (Path() / 'core' / 'dataset' / 'network' / 'malicious_example.pcap').resolve()
analysis = network_analyzer.analyze(str(pcap_file_path.as_posix()))

predictor = Predictor(DatasetType.NETWORK, output_feature='is_malicious')
prediction = predictor.predict(analysis)

# Make assurance and estimate clarity of prediction
accuracy = accuracy_score([1] * len(analysis), prediction)
print(accuracy)
