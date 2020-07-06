"""
Demo service plug-in
"""


def demo_service(data: dict = None):
    print(f'DEMO SERVICE GOT DATA: {data}')
    response = 'Demo proof of concept'
    if data is not None:
        data['response'] = response
        return data
    else:
        return response
