from garak.attempt import Message
from garak.generators.base import Generator


class GatewayGenerator(Generator):
    """Serial Garak text-chat adapter; initialization never probes the target."""
    generator_family_name = "FortiAIGate"
    parallel_capable = False
    supports_multiple_generations = False

    def __init__(self, model, transport):
        super().__init__(name=model)
        self.transport = transport
        self.attempt_id = None
        self.probe_id = None
        self.case_id = None
        self.last_request = None

    def _call_model(self, prompt, generations_this_call=1):
        self.last_request = self.transport.request(
            self._conversation_to_list(prompt), attempt_id=self.attempt_id, probe=self.probe_id,
            case_id=self.case_id)
        response = self.last_request["response"]
        if (self.last_request["gateway_outcome"] == "confirmed_block" or
                self.last_request["response_format"] not in ("openai_chat", "refusal")):
            return [None]
        return [Message(text=response) if response is not None else None]
