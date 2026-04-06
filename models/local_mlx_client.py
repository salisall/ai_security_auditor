import time
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple

# Lightweight adapter around mlx_lm to mimic the minimal interface used by BaseAuditor:
# self.model.chat.completions.create(messages=[...]) -> object with .choices[0].message.content


@dataclass
class _Message:
    role: str
    content: str


@dataclass
class _Choice:
    message: _Message


@dataclass
class _Completion:
    choices: List[_Choice]
    created: float


class LocalMLXChatCompletions:
    def __init__(self, generator_fn):
        self._generator_fn = generator_fn

    def create(self, messages: List[Dict[str, str]], **kwargs) -> _Completion:
        # Simple chat prompt formatting: concatenate messages as role: content
        prompt_parts: List[str] = []
        for m in messages:
            role = m.get('role', 'user')
            content = m.get('content', '')
            prompt_parts.append(f"{role}: {content}")
        prompt_parts.append("assistant:")
        prompt = "\n".join(prompt_parts)

        text: str = self._generator_fn(prompt, **kwargs)
        return _Completion(
            choices=[_Choice(message=_Message(role='assistant', content=text))],
            created=time.time(),
        )


class LocalMLXChat:
    def __init__(self, generator_fn):
        self.completions = LocalMLXChatCompletions(generator_fn)


class LocalMLXClient:
    def __init__(self, model_id: str, **gen_defaults):
        # Lazy import so environments without MLX can still import modules
        from mlx_lm import load, generate

        model, tokenizer = load(model_id)

        def _generate_fn(prompt: str, **kwargs) -> str:
            # Merge defaults with call-time kwargs
            params = {**gen_defaults, **kwargs}
            # Drop temperature params (some mlx versions don't accept it)
            params.pop('temperature', None)
            params.pop('temp', None)
            # Whitelist commonly supported params for mlx_lm.generate
            allowed = {
                'max_tokens', 'top_p', 'top_k', 'seed', 'repetition_penalty',
                'presence_penalty', 'frequency_penalty', 'stop', 'stream', 'verbose'
            }
            safe_params = {k: v for k, v in params.items() if k in allowed}
            # mlx_lm.generate returns a string
            return generate(model, tokenizer, prompt=prompt, **safe_params)

        self.chat = LocalMLXChat(_generate_fn)


