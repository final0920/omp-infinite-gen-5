"""Bytes at decoder-reported store locations around an owned native stop.

These are observations, not a proof of causal writes, CPU footprint completeness
or intermediate store order. No debugger command or native execution occurs here.
"""
import json
import time


def encode(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=True)


def reserve_store_event(stores):
    if len(stores) > 32 or sum(width for _, width, _ in stores) > 256:
        raise ValueError('Decoded store observations exceed 32 locations / 256 bytes')
    if any(type(address) is not int or not 0 <= address < 2**64 or type(width) is not int or not 1 <= width <= 256
           or address + width > 2**64 or len(data) != width for address, width, data in stores):
        raise ValueError('Invalid decoded store baseline')
    # Includes both hex byte strings plus bounded identity/status fields.
    return 512 + sum(192 + width * 4 for _, width, _ in stores)


def same_pause(current, expected, initial):
    return (current.get('state') == 'suspended'
            and all(current.get(key) == expected.get(key) for key in ('runId', 'pid', 'tid', 'stopSeq'))
            and all(current.get(key) == initial.get(key) for key in ('mainModuleBase', 'mainModuleSize')))


def capture_store_event(adapter, initial, before, after, ea, stores, group_index, deadline):
    reserve_store_event(stores)
    rows = []
    for address, width, baseline in stores:
        adapter.check()
        status, data = 'observed', None
        if time.monotonic() >= deadline:
            status = 'deadline'
        else:
            try:
                data = adapter.call('read_memory', address, width)
            except Exception as error:
                if getattr(error, 'code', None) in ('ECANCELLED', 'ETIMEDOUT', 'ETRANSPORT', 'EEXIT', 'EJOB'):
                    raise
                status = 'unavailable'
            if status == 'observed' and (not isinstance(data, bytes) or len(data) != width):
                status = 'unavailable'
        rows.append({'address': hex(address), 'bytes': width, 'beforeHex': baseline.hex(),
                     'afterHex': data.hex() if status == 'observed' else None,
                     'changed': baseline != data if status == 'observed' else None, 'status': status})
    matched = same_pause(adapter.context(), after, initial)
    if not matched:
        for row in rows:
            row.update(afterHex=None, changed=None, status='pause-changed')
    event = {'groupIndex': group_index, 'pc': hex(ea), 'beforeStopSeq': before['stopSeq'], 'afterStopSeq': after['stopSeq'],
             'pauseIdentityMatched': matched, 'completeDecodedStoreSet': matched and all(row['status'] == 'observed' for row in rows),
             'actualWriteCausalityProved': False, 'stores': rows}
    if len(encode(event)) > reserve_store_event(stores):
        raise ValueError('Store event exceeded its pre-step reservation')
    return event


def make_store_events(initial, last, trace_sha256, events):
    return {'schema': 'ig5.native-store-events.v1', 'runId': initial['runId'], 'threadId': initial['tid'],
            'runtimeBase': initial['mainModuleBase'], 'startStopSeq': initial['stopSeq'], 'endStopSeq': last['stopSeq'],
            'traceSha256': trace_sha256, 'scope': 'decoded-store-locations-observed-across-native-stop',
            'cpuWriteFootprintProved': False, 'storeOrder': 'decoder-enumeration-not-intermediate-write-order', 'events': events}
