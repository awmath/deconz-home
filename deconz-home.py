#!/usr/bin/env python3
# deconz-home - provides a connection of the deconz rest api to google assistant.
# Copyright (C) 2018 Axel Wegener <awmath@sparse-space.de>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import os
import flask
from argparse import ArgumentParser
from werkzeug.contrib.fixers import ProxyFix
import requests
import re
from hashlib import sha1
from colorsys import rgb_to_hsv, hsv_to_rgb
import configparser
from collections import defaultdict

app = flask.Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)


class PlatformDeconz:
    name = 'deconz'
    plugs = [
        ('OSRAM', 'Plug 01')
    ]

    def __init__(self, address, api_key, blacklist):
        self.request_base = 'http://{host}/api/{key}/' \
            .format(host=address, key=api_key)
        self.blacklist = blacklist

    def _get_light_data(self, entry):
        traits = ['action.devices.traits.OnOff']

        attributes = {}
        # check if light is actually a plug
        if (entry['manufacturername'], entry['modelid']) in self.plugs:
            device_type = 'action.devices.types.OUTLET'
        else:
            device_type = 'action.devices.types.LIGHT'
            # light can be dimmed
            if 'bri' in entry['state']:
                traits.append('action.devices.traits.Brightness')

            # light can change temperature
            if 'ct' in entry['state']:
                traits.append('action.devices.traits.ColorTemperature')
                attributes['temperatureMinK'] = 2000
                attributes['temperatureMaxK'] = 6500

            # light can change color
            if 'hue' in entry['state']:
                traits.append('action.devices.traits.ColorSpectrum')
                # even thought deconz uses hsv it's not documented well
                attributes['colorModel'] = 'rgb'

        return device_type, traits, attributes

    # def _get_light_data(self, entry):
    #     traits = ['action.devices.traits.OnOff']
    #     attributes = {}
    #     # check if light is actually a plug
    #     if (entry['manufacturername'], entry['modelid']) in self.plugs:
    #         device_type = 'action.devices.types.OUTLET'
    #     else:
    #         device_type = 'action.devices.types.LIGHT'
    #         # light can be dimmed
    #         if 'bri' in entry['state']:
    #             traits.append('action.devices.traits.Brightness')
    #         # light can change temperature
    #         if 'ct' in entry['state']:
    #             traits.append('action.devices.traits.ColorTemperature')
    #             attributes['temperatureMinK'] = 2000
    #             attributes['temperatureMaxK'] = 6500
    #         # light can change color
    #         if 'hue' in entry['state']:
    #             traits.append('action.devices.traits.ColorSpectrum')
    #             # even thought deconz uses hsv it's not documented well
    #             attributes['colorModel'] = 'rgb'
    #
    #     return device_type, traits, attributes

    def sync_payload(self):
        app.logger.debug('Sync called.')
        sync_devices = []

        # get deconz lights
        light_response = requests.get(self.request_base + 'lights')
        for deconz_id, entry in light_response.json().items():
            if entry['name'] in self.blacklist.get('lights', []):
                continue
            device_type, traits, attributes = self._get_light_data(entry)

            light = {
                'id': hash_string(get_mac(entry['uniqueid'])),
                'type': device_type,
                'traits': traits,
                'name': {
                    'defaultNames': [entry['type']],
                    'name': entry['name']
                },
                'willReportState': False, 'deviceInfo': {
                    'manufacturer': entry.get('manufacturername', ''),
                    'model': entry.get('modelid', ''),
                    'hwVersion': '',  # not given by deconz
                    'swVersion': entry.get('swversion', '')
                }, 'customData': {
                    'platform': 'deconz',
                    'type': 'lights',
                    'id': deconz_id
                }
            }

            # used to link deconz id with google device
            if attributes:
                light['attributes'] = attributes

            sync_devices.append(light)

        # get deconz sensors (turn them to thermostats for now)
        # since deconz splits temperature/humidity sensors we have to only find temperature sensors
        # humidity gets added on QUERY
        sensor_response = requests.get(self.request_base + 'sensors')
        for deconz_id, entry in sensor_response.json().items():
            if entry['name'] in self.blacklist.get('sensors', []):
                continue
            # only temperature sensors get added
            if not entry['type'] == 'ZHATemperature':
                continue

            sensor = {
                'id': hash_string(get_mac(entry['uniqueid'])),
                'type': 'action.devices.types.THERMOSTAT',
                'traits': ['action.devices.traits.TemperatureSetting'],
                'attributes': {
                    # only passive thermostat for now
                    'availableThermostatModes': 'off',
                    'thermostatTemperatureUnit': 'C'
                },
                'name': {
                    'defaultNames': [entry['type']],
                    'name': entry['name']
                },
                'willReportState': False,
                'deviceInfo': {
                    'manufacturer': entry.get('manufacturername', ''),
                    'model': entry.get('modelid', ''),
                    'hwVersion': '',  # not given by deconz
                    'swVersion': entry.get('swversion', '')
                },
                'customData': {
                    'platform': 'deconz',
                    'type': 'sensors',
                    'id': deconz_id  # used to link deconz id with google device
                }
            }

            # get deconz id of correspondig humidity sensor if available
            for hid, hval in sensor_response.json().items():
                if not hval['type'] == 'ZHAHumidity':
                    continue
                # check if mac adresses match
                if get_mac(entry['uniqueid']) == get_mac(hval['uniqueid']):
                    sensor['customData']['hid'] = hid
                    break

            sync_devices.append(sensor)

        config = requests.get(self.request_base + 'config').json()
        group_response = requests.get(self.request_base + 'groups')
        for deconz_id, entry in group_response.json().items():
            # create a (pseudo) unique id from bridge_id and name hash
            if entry['name'] in self.blacklist.get('groups', []):
                continue
            group = {'id': hash_string('{id}_{name}'.format(id=config['bridgeid'], name=entry['name']))}

            # check if group is hidden or automically created
            if entry['hidden'] or entry['devicemembership']:
                continue

            # check all group members in order to get common types/traits
            type_set = set()
            trait_set = set()
            attributes = {}
            if not entry['lights']:
                continue
            for device_id in entry['lights']:
                device_type, device_traits, device_attributes = self._get_light_data(light_response.json()[device_id])
                type_set.add(device_type)
                for trait in device_traits:
                    trait_set.add(trait)
                for attribute, value in device_attributes.items():
                    attributes[attribute] = value

            # # check if all types are the same
            # # otherwise just make an arbitrary lights group
            # if len(type_set) == 1:
            #     group['type'] = type_set.pop()
            # else:
            #     group['type'] = 'action.devices.types.LIGHT'

            # suggested type for mixed is SWITCH
            group['type'] = 'action.devices.types.SWITCH'

            group['traits'] = list(trait_set)
            if attributes:
                group['attributes'] = attributes
            group['name'] = {
                'defaultNames': [entry['type']],
                'name': entry['name']
            }
            group['willReportState'] = False
            group['deviceInfo'] = {
                'manufacturer': config.get('devicename', ''),
                'model': config.get('modelid', ''),
                'hwVersion': config.get('fwversion', ''),
                'swVersion': config.get('swversion', '')
            }

            # used to link deconz id with google device
            group['customData'] = {
                'platform': 'deconz',
                'type': 'groups',
                'id': deconz_id
            }

            sync_devices.append(group)
        app.logger.debug('Sync complete with {0} devices.'.format(len(sync_devices)))
        return sync_devices

    def execute(self, device, executions):
        put_data = {}
        for execution in executions:
            if execution['command'] == 'action.devices.commands.OnOff':
                put_data['on'] = execution['params']['on']
            elif execution['command'] == 'action.devices.commands.BrightnessAbsolute':
                # map google brightness range to deconz
                brightness = round(execution['params']['brightness'] / 100 * 255)
                if brightness > 0:
                    put_data['bri'] = brightness
                    put_data['on'] = True
                else:
                    put_data['bri'] = 0
                    put_data['on'] = False
            elif execution['command'] == 'action.devices.commands.ColorAbsolute':
                if 'temperature' in execution['params']['color']:
                    # transform temperature from google kelvin to deconz mireds
                    mireds = round(1e6 / execution['params']['color']['temperature'])
                    put_data['ct'] = mireds
                else:
                    # transform color from google integer RGB to deconz hue saturation
                    [hue, saturation, brightness] = int_to_hsv(execution['params']['color']['spectrumRGB'])
                    # get hue as 16bit int, sat as 8bit int and val as 8bit int
                    hue = hue * 65535
                    saturation = round(saturation * 255)
                    brightness = round(brightness)
                    if brightness > 0:
                        put_data['bri'] = brightness
                        put_data['on'] = True
                    else:
                        put_data['bri'] = 0
                        put_data['on'] = False
                    put_data['hue'] = hue
                    put_data['sat'] = saturation

        if device['customData']['type'] == 'groups':
            endpoint = 'action'
        else:
            endpoint = 'state'
        request_url = self.request_base + '{type}/{id}/{point}' \
            .format(type=device['customData']['type'], id=device['customData']['id'], point=endpoint)
        response = requests.put(request_url, json=put_data)

        error_code = None
        if response.status_code == 404:
            app.logger.debug('Request Error {p} as {r}: {m} \n payload: {pl}'
                             .format(p=response.status_code, r=request_url, m=response.text, pl=response.request.body))
            error_code = 'protocolError'
            return error_code

        response_json = response.json()
        if response.status_code == 200:
            # check if deconz can't talk to device
            if 'error' in response_json:
                error_code = 'deviceOffline'
        else:
            app.logger.debug('Request Error {p} as {r}: {m} \n payload: {pl}'
                             .format(p=response.status_code, r=request_url, m=response.text, pl=response.request.body))
            error_code = 'protocolError'

        return error_code

    def query(self, device):
        request_url = self.request_base + '{type}/{id}' \
            .format(type=device['customData']['type'], id=device['customData']['id'])
        response = requests.get(request_url)

        error_code = None
        if response.status_code == 404:
            app.logger.debug('Request Error {p}: {r}'.format(p=response.status_code, r=request_url))
            app.logger.debug(response.request.body)
            error_code = 'protocolError'
            return error_code, None

        response_json = response.json()
        if response.status_code == 200:
            # check if deconz can't talk to device
            if 'error' in response_json:
                error_code = 'deviceOffline'
        else:
            app.logger.debug('Request Error {p}: {r}'.format(p=response.status_code, r=request_url))
            app.logger.debug(response.request.body)
            error_code = 'protocolError'

        if device['customData']['type'] == 'lights':
            states = {
                'on': response_json['state']['on'],
                'online': response_json['state']['reachable']
            }
            if 'bri' in response_json['state']:
                states['brightness'] = round(response_json['state']['bri'] * 100 / 255)
            if 'ct' in response_json['state']:
                states['color'] = {
                    # todo: color name with color library
                    'temperature': round(1e6 / response_json['state']['ct'])
                }
            if 'hue' in response_json['state']:
                states['color'] = {
                    # todo: color name with color library
                    'spectrumRGB': hsv_to_int(response_json['state']['hue'] / 65535,
                                              response_json['state']['sat'] / 255,
                                              response_json['state']['bri'])
                }
        elif device['customData']['type'] == 'sensors':
            states = {
                'online': response_json['config']['reachable'],
                'thermostatTemperatureAmbient': float(response_json['state']['temperature'])/100
            }
            if 'hid' in device['customData']:
                humid_request_url = self.request_base + '{type}/{id}' \
                    .format(type=device['customData']['type'], id=device['customData']['hid'])

                states['thermostatHumidityAmbient'] = \
                    float(requests.get(humid_request_url).json()['state']['humidity'])/100

        return error_code, states


@app.route('/')
def index():
    return 'index'


@app.route('/api/google/authorization')
def authenticate():
    # check
    client_id = flask.request.args.get('client_id')
    redirect_uri = flask.request.args.get('redirect_uri')
    state = flask.request.args.get('state')
    # response type always token
    if not (flask.request.args.get('response_type') == 'token'):
        app.logger.debug('/api/google/authorization Authorization failed: wrong response type.')
        return 'Authorization failed: wrong response type.'

    if not (redirect_uri == 'https://oauth-redirect.googleusercontent.com/r/{project_id}'
            .format(project_id=app.config['GOOGLE_PROJECT_ID'])):
        app.logger.debug('/api/google/authorization Authorization failed: redirect_url not matching.')
        return 'Authorization failed: redirect_url not matching.'

    if not (client_id == app.config['GOOGLE_CLIENT_ID']):
        app.logger.debug('/api/google/authorization Authorization failed: client_id not matching.')
        return 'Authorization failed: client_id not matching.'

    redirection = '{redirect}#access_token={token}&token_type=bearer&state={state}' \
        .format(redirect=redirect_uri, token=app.config['GOOGLE_ACCESS_TOKEN'], state=state)
    return flask.redirect(redirection)


@app.route('/api/google/assistant', methods=['GET', 'POST'])
def google_actions():
    app.logger.debug(flask.request.get_json(force=True))
    # check authorization header
    if flask.request.headers['Authorization'] != 'Bearer {token}'.format(token=app.config['GOOGLE_ACCESS_TOKEN']):
        return flask.jsonify({}), 401
    request_json = flask.request.get_json(force=True)
    response = {'requestId': request_json['requestId']}
    action = request_json['inputs'][0]
    # smart home only has a single intent
    if action['intent'] == 'action.devices.EXECUTE':
        response['payload'] = execute_google_request(action['payload']['commands'])
    elif action['intent'] == 'action.devices.SYNC':
        response['payload'] = get_sync_payload()
    elif action['intent'] == 'action.devices.QUERY':
        response['payload'] = get_query_payload(action['payload']['devices'])
    else:
        response = {}

    app.logger.debug(flask.json.dumps(response))
    return flask.jsonify(response)


@app.route('/api/google/assistant/request_sync')
def google_request_sync():
    app.logger.debug('SYNC requested.')
    request_url = 'https://homegraph.googleapis.com/v1/devices:requestSync?key={api_key}' \
        .format(api_key=app.config['GOOGLE_HOMEGRAPH_KEY'])
    request_data = {'agent_user_id': app.config['GOOGLE_AGENT_USER_ID']}
    response = requests.post(request_url, data=request_data)
    if response.status_code == 200:
        return 'Request sync successful.'
    else:
        return 'Request sync failed with code {code}: {message}'.format(code=response.json()['error']['code'],
                                                                        message=response.json()['error']['message'])


def execute_google_request(commands):
    # dictionary definitions for response
    success = []
    errors = defaultdict(list)
    for command in commands:
        for device in command['devices']:
            # reach execute command to correct platform
            platform = device['customData']['platform']
            error = providers[platform].execute(device=device, executions=command['execution'])
            if not error:
                success.append(device['id'])
            else:
                errors[error].append(device['id'])

    app.logger.debug(errors)

    payload = {'commands': []}
    if success:
        payload['commands'].append({
            'ids': success,
            'status': 'SUCCESS'
        })
    for error_key, error_ids in errors.items():
        payload['commands'].append({
            'ids': error_ids,
            'status': 'ERROR',
            'errorCode': error_key
        })

    return payload


def get_mac(string):
    p = re.compile('([0-9a-f]{2}(?::[0-9a-f]{2})*)', re.IGNORECASE)
    return re.findall(p, string)[0]


def hash_string(text):
    return sha1(text.encode('utf-8')).hexdigest()


def int_to_hsv(rgb_int):
    blue = rgb_int & 255
    green = (rgb_int >> 8) & 255
    red = (rgb_int >> 16) & 255
    return rgb_to_hsv(red, green, blue)


def hsv_to_int(hue, saturation, value):
    red, green, blue = hsv_to_rgb(hue, saturation, value)
    return (red << 16) + (green << 8) + blue


def get_sync_payload():
    sync_data = {'agentUserId': app.config['GOOGLE_AGENT_USER_ID']}
    sync_devices = []
    for provider, instance in providers.items():
        sync_devices += instance.sync_payload()

    sync_data['devices'] = sync_devices
    return sync_data


def get_query_payload(devices):
    # dictionary definitions for response
    payload = {
        'devices': {}
    }
    for device in devices:
        # reach execute command to correct platform
        platform = device['customData']['platform']
        error, states = providers[platform].query(device)
        if not error:
            payload['devices'][device['id']] = states
        else:
            payload['devices']['errorCode'] = error

    return payload


if __name__ == '__main__':
    # small argument parsing passage to handle secret key files
    parser = ArgumentParser()
    parser.add_argument('-c', '--config', type=str, default='server.conf')
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()



    if not os.path.exists(args.config):
        print('Error: config file: {0} does not exist'.format(args.config))
        exit(1)

    config = configparser.ConfigParser()
    config.read(args.config)

    app.config.update(
        GOOGLE_CLIENT_ID=config['google']['client_id'],
        GOOGLE_ACCESS_TOKEN=config['google']['access_token'],
        GOOGLE_REDIRECT_URL=config['google']['redirect_url'],
        GOOGLE_PROJECT_ID=config['google']['project_id'],
        GOOGLE_AGENT_USER_ID=config['google']['agent_user_id'],
        GOOGLE_HOMEGRAPH_KEY=config['google']['homegraph_api_key']
    )

    app.secret_key = config['flask']['secret']

    global providers
    providers = dict(deconz=PlatformDeconz(address=config['deconz']['host'], api_key=config['deconz']['api_key'],
                                           blacklist=config['blacklist']))
    app.run(host=config['flask']['host'], port=int(config['flask']['port']),
            debug=config.getboolean('flask', 'debug') or args.debug)
