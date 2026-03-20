# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 PiQrypt Inc.
# e-Soleau: DSO2026006483 (19/02/2026) -- DSO2026009143 (12/03/2026)
import sys
import types
import hashlib
import json
from unittest.mock import MagicMock
events = []
mock_pq = types.ModuleType('piqrypt')
mock_pq.generate_keypair = lambda: (b'priv'*8, b'pub'*8)
mock_pq.derive_agent_id = lambda pub: 'AGENT_'+hashlib.sha256(pub).hexdigest()[:12]
mock_pq.load_identity = lambda f: {'private_key_bytes': b'key'*8, 'agent_id': 'AGENT_TEST'}
mock_pq.stamp_event = lambda key, aid, payload: {**payload, '_pq_agent_id': aid, '_pq_sig': 'mock'}
mock_pq.store_event = lambda e: events.append(e)
mock_pq.compute_event_hash = lambda e: hashlib.sha256(json.dumps(e, default=str).encode()).hexdigest()
mock_pq.export_audit_chain = lambda path: open(path, 'w').write(json.dumps(events))
sys.modules['piqrypt'] = mock_pq
ag = types.ModuleType('autogen')


class CA:
    def __init__(self, **k):
        self.name = k.get('name', 'a')
        self._reply_func_list = []

    def generate_reply(self, **k):
        return 'mock'

    def initiate_chat(self, r, message='', **k):
        return MagicMock(summary='ok')

    def register_reply(self, *a, **k):
        pass


class AA(CA):
    pass


class UA(CA):
    def __init__(self, **k):
        super().__init__(**k)
        self.human_input_mode = 'TERMINATE'
        self.code_execution_config = False

    def execute_code_blocks(self, *a, **k):
        return 0, 'ok'


ag.ConversableAgent = CA
ag.AssistantAgent = AA
ag.UserProxyAgent = UA
sys.modules['autogen'] = ag
sys.modules['pyautogen'] = ag
