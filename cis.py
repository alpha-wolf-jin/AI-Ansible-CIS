#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2012, Dag Wieers (@dagwieers) <dag@wieers.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later


from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = r'''
---
author:
- Jin Zhang
module: ai_cis
short_description: Read input from tensor and give the cis remediaton item
description:
'''

EXAMPLES = r'''

'''

import errno
import os
import platform
import random
import re
import string

import pandas as pd
import nltk
import re
import pickle
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from sklearn.feature_extraction.text import CountVectorizer

from ansible.module_utils.basic import AnsibleModule, get_platform, get_distribution
from ansible.module_utils.six import iteritems


def main():

    module = AnsibleModule(
        argument_spec=dict(
            model=dict(type='str', required=True),
            csv_report=dict(type='str', required=True),
            features=dict(type='str', required=True),
        ),
        #required_together=[['csv']],
    )

    model = module.params.get('model')
    csv_report = module.params.get('csv_report')
    features = module.params.get('features')

    code = 0
    secure_state = False

    report = pd.read_csv(csv_report)
    report.drop(['Plugin', 'Plugin Name', 'Severity', 'IP Address', 'Description', 'See Also', 'First Discovered', 'Last Observed'], axis='columns', inplace=True)
    #query_list = report['Plugin Output'].tolist()

    data = pd.read_csv(features)

    nltk.download('stopwords')
    nltk.download('wordnet')
    
    text = list(data['text'])
    
    lemmatizer = WordNetLemmatizer()
    
    corpus = []
    
    for i in range(len(text)):
    
        r = re.sub('[^a-zA-Z]', ' ', text[i])
    
        r = r.lower()
    
        r = r.split()
    
        r = [word for word in r if word not in stopwords.words('english')]
    
        r = [lemmatizer.lemmatize(word) for word in r]
    
        r = ' '.join(r)
    
        corpus.append(r)
    
    
    cv = CountVectorizer()
    
    cv.fit_transform(corpus)
    

    query_list = []
    for  question in report['Plugin Output'].tolist():
      question = " ".join(question.split()[:100])
      
      r = re.sub('[^a-zA-Z]', ' ', question)
      
      r = r.lower()
      
      r = r.split()
      r = [word for word in r if word not in stopwords.words('english')]
      
      r = [lemmatizer.lemmatize(word) for word in r]
      
      r = ' '.join(r)
      
      query_list.append(r)


    query = pd.Series(query_list)
    query_cv = cv.transform(query)
    
    
    filename = 'finalized_model.sav'
    loaded_model = pickle.load(open(filename, 'rb'))
    predictions = loaded_model.predict(query_cv)
    
    #cis_list.append(predictions.tolist()[0])
 
    cis_list = []
    for i in predictions.tolist():
      cis_list.append("{}".format(i))

    result = dict(
        changed=False,
        cis=cis_list)


    module.exit_json(msg='CIS Policy: ' + str(result['cis']), result=result)


if __name__ == '__main__':
    main()
