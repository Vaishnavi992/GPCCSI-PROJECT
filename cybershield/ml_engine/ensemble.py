"""Soft-voting ensemble — must live here so joblib can find it on load."""
import numpy as np

class Ensemble:
    def __init__(self, models, weights):
        self.models = models
        w = np.array(weights, dtype=float)
        self.w = w / w.sum()
        self.classes_ = models[0].classes_

    def predict_proba(self, X):
        return sum(m.predict_proba(X) * w for m, w in zip(self.models, self.w))

    def predict(self, X):
        return np.argmax(self.predict_proba(X), axis=1)
