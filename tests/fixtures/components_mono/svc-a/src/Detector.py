"""Signal-bearing module inside the svc-a build component."""

import pickle


def handle(untrusted_payload, user_expression):
    obj = pickle.loads(untrusted_payload)
    eval(user_expression)
    return obj
