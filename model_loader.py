"""Load the existing model artifact with a narrowly scoped sklearn shim."""

import threading

import joblib
import joblib.numpy_pickle as numpy_pickle


_LOAD_LOCK = threading.Lock()


def load_model_artifact(path):
    """Load a joblib artifact while mapping one proven legacy sklearn global."""
    from sklearn._loss._loss import CyHalfBinomialLoss

    original_find_class = numpy_pickle.NumpyUnpickler.find_class

    def find_class(unpickler, module, name):
        if module == "_loss" and name == "CyHalfBinomialLoss":
            return CyHalfBinomialLoss
        return original_find_class(unpickler, module, name)

    with _LOAD_LOCK:
        numpy_pickle.NumpyUnpickler.find_class = find_class
        try:
            return joblib.load(path)
        finally:
            numpy_pickle.NumpyUnpickler.find_class = original_find_class