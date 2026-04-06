from enum import Enum

class AIModel(Enum):
    DEEPSEEK_R1 = 'deepseek-r1'
    LLAMA3_1 = 'llama3.1'
    QWEN3 = 'qwen3'
    GEMMA3 = 'gemma3'
    GEMMA2_LOCAL = 'gemma2_local'

AI_models = {
    'deepseek-r1': {
        'model': 'deepseek-ai/DeepSeek-R1',
        'provider': 'sambanova',
    },
    'llama3.1': {
        'model': 'meta-llama/Llama-3.1-8B-Instruct',    
        'provider': 'sambanova',
    },
    'qwen3': {
        'model': 'Qwen/Qwen3-8B',
        'provider': 'nscale',
    },
    'gemma3': {
        'model': 'google/gemma-2-2b-it',
        'provider': 'nebius',
    },
    'gemma2_local': {
        'model': 'google/gemma-2-2b-it',
        'provider': 'local_mlx',
    },
    
}