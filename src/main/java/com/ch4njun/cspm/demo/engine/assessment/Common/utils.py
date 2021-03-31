import datetime, maya
from pytz import timezone
from Common.data import low_data

def from_now(date):
    return (datetime.datetime.now(timezone('Asia/Seoul')) - date).days

def append_data(data, cli, raw_data):
    if cli and cli not in data['cli']:
        data['cli'].append(cli)
        data['raw_data'].append(raw_data)

def append_summary(data, summary):
    if summary and summary not in data['summary']:
        data['summary'].append(summary)

def get_resources(data):
    return [key_data for tmp_data in data['data'] for key_data in tmp_data.keys()]

def pref(x):
    if x == '&':
        return 1
    elif x == '|':
        return 0
    elif x == '(' or x == ')':
        return -1

def cloudwatch_parse(metric_filter, dictionary, flag=True):
    target_metric_filter = metric_filter.lstrip('{').rstrip('}').replace('&&', '&').replace('||', '|').replace(' ', '')
    token_list = []
    token = ''

    num = 10831
    for index, char in enumerate(target_metric_filter):
        if char in ['|', '&', '(', ')']:
            if token:
                if flag:
                    dictionary[token] = num
                    num += 991
                token_list.append(token)
                token = ''
            token_list.append(char)
        else:
            token += char
    if token:
        if flag:
            dictionary[token] = num
            num += 991
        token_list.append(token)

    stack = []
    postfix = []
    for token in token_list:
        if token not in ['&', '|', '(', ')']:
            postfix.append(token)
        elif token in ['&', '|']:
            p = pref(token)
            while len(stack) > 0:
                top = stack[-1]
                if pref(top) <= p:
                    break
                postfix.append(stack.pop())
            stack.append(token)
        elif token in ['(']:
            stack.append(token)
        elif token in [')']:
            while True:
                top = stack.pop()
                if top == '(':
                    break
                postfix.append(top)
    while len(stack) > 0:
        postfix.append(stack.pop())

    stack = []
    for token in postfix:
        if token not in ['&', '|']:
            if flag or token in dictionary:
                stack.append(dictionary[token])
            else:
                return 0
        else:
            x = stack.pop()
            y = stack.pop()
            if token == '&':
                stack.append(x * y)
            elif token == '|':
                stack.append(x + y)
    return stack.pop()

