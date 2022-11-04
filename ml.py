from sklearn import svm
from sklearn import tree
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import minmax_scale
from mlxtend.classifier import EnsembleVoteClassifier
import numpy
import os
import pandas as pd
from collections import deque
import warnings
warnings.filterwarnings("ignore")


class MachineLearningAlgo:
    def __init__(self):
        # Hybrid
        clf1 = svm.SVC(kernel="rbf", probability=True,
                       random_state=0, gamma=0.001, C=100)
        clf2 = RandomForestClassifier(
            n_estimators=6, max_depth=None, min_samples_split=2, random_state=0)
        clf3 = MLPClassifier(hidden_layer_sizes=(
            250, 150, 100), activation="relu", solver='adam', random_state=1)

        self.clf = EnsembleVoteClassifier(clfs=[clf1, clf2, clf3],
                                          weights=[1, 1, 1], voting='soft')
        print("Using Hybrid Algo (SVM + RF + MLP) ")

        X_train = pd.read_csv('result.csv')
        y_train = X_train["type"]
        del X_train["type"]
        X_train.iloc[:] = minmax_scale(X_train.iloc[:])
        self.clf.fit(X_train, y_train.values.ravel())

    def classify(self, data):
        prediction = self.clf.predict(data)
        print("prediction result ", prediction)
        return prediction
