# File: isightpartners_views.py
# Copyright (c) 2014-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.


def get_report(provides, all_results, context):

    context['results'] = results = []

    headers = ['Report ID', 'Report Title', 'Publish Date']
    context['headers'] = headers

    for summary, action_results in all_results:
        for result in action_results:
            table = dict()
            table['data'] = rows = []
            data = result.get_data()

            for item in data:
                row = []
                if not item.get('report'):
                    continue
                row.append({'value': item.get('report').get('reportId')})
                row.append({'value': item.get('report').get('title')})
                row.append({'value': item.get('report').get('publishDate')})
                rows.append(row)
            results.append(table)

    return 'isightpartners_get_report.html'
