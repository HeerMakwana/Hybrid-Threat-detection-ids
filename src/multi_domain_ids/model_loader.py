"""Load the existing model artifact with a narrowly scoped sklearn shim."""

import sys
import threading
import types

import joblib
import joblib.numpy_pickle as numpy_pickle
import numpy as np


class ProbabilityCalibrator:
    """Compatibility stub for the legacy pickled wrapper class."""

    def __init__(self, estimator, calibrator):
        self.estimator = estimator
        self.calibrator = calibrator

    def predict_proba(self, X):
        p = self.estimator.predict_proba(X)[:, 1]
        if hasattr(self.calibrator, "transform"):
            calibrated = self.calibrator.transform(p)
        else:
            calibrated = self.calibrator.predict_proba(p.reshape(-1, 1))[:, 1]
        return np.column_stack([1.0 - calibrated, calibrated])

    def predict(self, X):
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)


_LOAD_LOCK = threading.Lock()


def _install_legacy_compat_modules():
    legacy_module = sys.modules.get("train_model")
    if legacy_module is None:
        legacy_module = types.ModuleType("train_model")
        sys.modules["train_model"] = legacy_module
    legacy_module.ProbabilityCalibrator = ProbabilityCalibrator


def load_model_artifact(path):
    """Load a joblib artifact while mapping legacy sklearn globals and modules."""
    _install_legacy_compat_modules()
    from sklearn._loss._loss import CyHalfBinomialLoss

    original_find_class = numpy_pickle.NumpyUnpickler.find_class

    def find_class(unpickler, module, name):
        if module == "_loss" and name == "CyHalfBinomialLoss":
            return CyHalfBinomialLoss
        if module == "train_model" and name == "ProbabilityCalibrator":
            return ProbabilityCalibrator
        return original_find_class(unpickler, module, name)

    with _LOAD_LOCK:
        numpy_pickle.NumpyUnpickler.find_class = find_class
        try:
            return joblib.load(path)
        finally:
            numpy_pickle.NumpyUnpickler.find_class = original_find_class
