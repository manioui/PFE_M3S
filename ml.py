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

#Cette classe est utilisée dans Ids_app.py pour la détection des DDoS.
class MachineLearningAlgo:
    def __init__(self):
        # Initialisation des classificateurs et aussi Hybrid
        clf1 = svm.SVC(kernel="rbf", probability=True,
                       random_state=0, gamma=0.001, C=100)
        clf2 = RandomForestClassifier(
            n_estimators=6, max_depth=None, min_samples_split=2, random_state=0)
        clf3 = MLPClassifier(hidden_layer_sizes=(
            250, 150, 100), activation="relu", solver='adam', random_state=1)

        self.clf = EnsembleVoteClassifier(clfs=[clf1, clf2, clf3],
                                          weights=[1, 1, 1], voting='soft')
        print("Using Hybrid Algo (SVM + RF + MLP) ")
	#chargement des données 
        X_train = pd.read_csv('result.csv')
        y_train = X_train["type"]
        del X_train["type"]
        X_train.iloc[:] = minmax_scale(X_train.iloc[:])
	#entraîner notre modèle final
        self.clf.fit(X_train, y_train.values.ravel())

    def classify(self, data):
	#faire une prédiction
        prediction = self.clf.predict(data)
	#Montrer la prédiction prévues
        print("prediction result ", prediction)
        return prediction
