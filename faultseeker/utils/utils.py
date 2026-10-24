import os
import re
import json
from faultseeker.utils.agent import OllmaAgent, GPTAgent


def check_cache(cache_dir, keyword):
    keyword = keyword.lower()
    if os.path.exists(os.path.join(cache_dir, f"{keyword}.json")):
        return json.load(open(os.path.join(cache_dir, f"{keyword}.json"), 'r'))
    return None

def get_transaction_hash(txn_link):
    pattern = r'(0x[0-9a-fA-F]{64})'
    return re.findall(pattern, txn_link)

def get_common_address(chain):
    address_dict = {
        'mainnet': [
            '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D',
            '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
            '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
            '0xdAC17F958D2ee523a2206206994597C13D831ec7',
            '0x4Fabb145d64652a948d72533023f6E7A623C7C53',
            '0xB8c77482e45F1F44dE1745F52C74426C631bDD52',
            '0x6B175474E89094C44Da98b954EedeAC495271d0F',
            '0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599',
            '0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f'
        ],
        'eth': [
            '0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D',
            '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2',
            '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
            '0xdAC17F958D2ee523a2206206994597C13D831ec7',
            '0x4Fabb145d64652a948d72533023f6E7A623C7C53',
            '0xB8c77482e45F1F44dE1745F52C74426C631bDD52',
            '0x6B175474E89094C44Da98b954EedeAC495271d0F',
            '0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599',
            '0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f'
        ],
        'bsc': [
            '0x10ED43C718714eb63d5aA57B78B54704E256024E',
            '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c',
            '0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d',
            '0x55d398326f99059fF775485246999027B3197955',
            '0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56',
            '0x2170Ed0880ac9A755fd29B2688956BD959F933F8',
            '0x1AF3F329e8BE154074D8769D1FFa4eE058B1DBc3',
            '0x1CE0c2827e2eF14D5C4f29a091d735A204794041',
            '0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73'
        ],
        'polygon': [
            '0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff',
            '0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270',
            '0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174',
            '0xc2132D05D31c914a87C6611C10748AEb04B58e8F',
            '0xdAb529f40E671A1D4bF91361c21bf9f0C9712ab7',
            '0x8f3Cf7ad23Cd3CaDbD9735AFf958023239c6A063',
            '0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619',
            '0x1BFD67037B42Cf73acF2047067bd4F2C47D9BfD6',
        ],
        'avalanche': [
            '0x60aE616a2155Ee3d9A68541Ba4544862310933d4',
            '0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7',
            '0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E',
            '0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7',
            '0x2b2C81e08f1Af8835a78Bb2A90AE924ACE0eA4bE',
            '0xA7D7079b0FEaD91F3e65f86E8915Cb59c1a4C664',
            '0xc7198437980c041c805A1EDcbA50c1Ce5db95118',
            '0x19860CCB0A68fd4213aB9D8266F7bBf05A8dDe98',
            '0xA3f5B2C8D4E6F7b9C1D5F4e8E2c3A7d6B1aF4b8C',
        ],
        'optimism': [
            '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45',
            '0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7',
            '0x7F5c764cBc14f9669B88837ca1490cCa17c31607',
            '0x94b008aA00579c1307B0EF2c499aD98a8ce58e58',
            '0x68f180fcCe6836688e9084f035309E29Bf0A2095',
            '0xC22885e06cd8507c5c74a948C59af853AEd1Ea5C',
            '0x8c6f28f2F1A3C87F0f938b96d27520d9751ec8d9',
            '0x298B9B95708152ff6968aafd889c6586e9169f1D',
            '0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f',
        ],
        'fantom': [
            '0xF491e7B69E4244ad4002BC14e878a34207E38c29',
            '0xe1146b9AC456fCbB60644c36Fd3F868A9072fc6E',
            '0x658b0c7613e890EE50B8C4BC6A3f41ef411208aD',
            '0x04068DA6C83AFCFA0e13ba15A6696662335D5B75',
            '0x8D11eC38a3EB5E956B052f67Da8Bdc9bef8Abf3E',
            '0x511D35c52a3C244E7b8bd92c0C297755FbD89212',
            '0x321162Cd933E2Be498Cd2267a90534A804051b11',
            '0xcf799767d366d789e8B446981C2D578E241fa25c',
            '0x3C5D4E8F2A7B1C6D9E4F5A0B8E2C3A7D6B1aF4b8C',
        ],
        'arbitrum': [
            '0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506',
            '0x82aF49447D8a07e3bd95BD0d56f35241523fBab1',
            '0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8',
            '0xd4d42F0b6DEF4CE0383636770eF773390d85c61A',
            '0xDA10009cBd5D07dd0CeCc66161FC93D7c9000da1',
            '0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f',
        ],
        'pulsechain': [
            '0x98bf93ebf5c380C0e6Ae8e192A7e2AE08edAcc02',
            '0xA1077a294dDE1B09bB078844df40758a5D0f9a27',
            '0x0Cb6F5a34ad42ec934882A05265A7d5F59b51A2f',
            '0x15D38573d2feeb82e7ad5187aB8c1D52810B1f07',
            '0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc',
        ],
        'base': [
            '0xfCD3842f85ed87ba2889b4D35893403796e67FF1',
            '0x4200000000000000000000000000000000000006'
        ]
    }
    if chain not in address_dict:
        return []
    return address_dict[chain]

def get_common_address_lower(chain):
    address_dict = {
        'mainnet': [
            '0x7a250d5630b4cf539739df2c5dacb4c659f2488d',
            '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2',
            '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
            '0xdac17f958d2ee523a2206206994597c13d831ec7',
            '0x4fabb145d64652a948d72533023f6e7a623c7c53',
            '0xb8c77482e45f1f44de1745f52c74426c631bdd52',
            '0x6b175474e89094c44da98b954eedeac495271d0f',
            '0x2260fac5e5542a773aa44fbcfedf7c193bc2c599',
            '0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f'
        ],
        'eth': [
            '0x7a250d5630b4cf539739df2c5dacb4c659f2488d',
            '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2',
            '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
            '0xdac17f958d2ee523a2206206994597c13d831ec7',
            '0x4fabb145d64652a948d72533023f6e7a623c7c53',
            '0xb8c77482e45f1f44de1745f52c74426c631bdd52',
            '0x6b175474e89094c44da98b954eedeac495271d0f',
            '0x2260fac5e5542a773aa44fbcfedf7c193bc2c599',
            '0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f'
        ],
        'bsc': [
            '0x10ed43c718714eb63d5aa57b78b54704e256024e',
            '0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c',
            '0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d',
            '0x55d398326f99059ff775485246999027b3197955',
            '0xe9e7cea3dedca5984780bafc599bd69add087d56',
            '0x2170ed0880ac9a755fd29b2688956bd959f933f8',
            '0x1af3f329e8be154074d8769d1ffa4ee058b1dbc3',
            '0x1ce0c2827e2ef14d5c4f29a091d735a204794041',
            '0xca143ce32fe78f1f7019d7d551a6402fc5350c73'
        ],
        'polygon': [
            '0xa5e0829caced8ffdd4de3c43696c57f7d7a678ff',
            '0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270',
            '0x2791bca1f2de4661ed88a30c99a7a9449aa84174',
            '0xc2132d05d31c914a87c6611c10748aeb04b58e8f',
            '0xdab529f40e671a1d4bf91361c21bf9f0c9712ab7',
            '0x8f3cf7ad23cd3cadbd9735aff958023239c6a063',
            '0x7ceb23fd6bc0add59e62ac25578270cf1b9f619',
            '0x1bfd67037b42cf73acf2047067bd4f2c47d9bf6',
        ],
        'avalanche': [
            '0x60ae616a2155ee3d9a68541ba4544862310933d4',
            '0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7',
            '0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e',
            '0x9702230a8ea53601f5cd2dc00fdb13d4df4a8c7',
            '0x2b2c81e08f1af8835a78bb2a90ae924ace0ea4be',
            '0xa7d7079b0fead91f3e65f86e8915cb59c1a4c664',
            '0xc7198437980c041c805a1edcba50c1ce5db95118',
            '0x19860ccb0a68fd4213ab9d8266f7bbbf05a8dde98',
            '0xa3f5b2c8d4e6f7b9c1d5f4e8e2c3a7d6b1af4b8c',
        ],
        'optimism': [
            '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45',
            '0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7',
            '0x7f5c764cbc14f9669b88837ca1490cca17c31607',
            '0x94b008aa00579c1307b0ef2c499ad98a8ce58e58',
            '0x68f180fcce6836688e9084f035309e29bf0a2095',
            '0xc22885e06cd8507c5c74a948c59af853aed1ea5c',
            '0x8c6f28f2f1a3c87f0f938b96d27520d9751ec8d9',
            '0x298b9b95708152ff6968aafd889c6586e9169f1d',
            '0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f',
        ],
        'fantom': [
            '0xf491e7b69e4244ad4002bc14e878a34207e38c29',
            '0xe1146b9ac456fcb606644c36fd3f868a9072fc6e',
            '0x658b0c7613e890ee50b8c4bc6a3f41ef411208ad',
            '0x04068da6c83afcfA0E13ba15A6696662335D5B75',
            '0x8d11ec38a3eb5e956b052f67da8bdc9bef8abf3e',
            '0x511d35c52a3c244e7b8bd92c0c297755fbd89212',
            '0x321162cd933e2be498cd2267a90534a804051b11',
            '0xcf799767d366d789e8b446981c2d578e241fa25c',
            '0x3c5d4e8f2a7b1c6d9e4f5a0b8e2c3a7d6b1af4b8c',
        ],
        'arbitrum': [
            '0x1b02da8cb0d097eb8d57a175b88c7d8b47997506',
            '0x82af49447d8a07e3bd95bd0d56f35241523fbab1',
            '0xff970a61a04b1ca14834a43f5de4533ebdddb5cc8',
            '0xd4d42f0b6def4ce0383636770ef773390d85c61a',
            '0xda10009cbd5d07dd0cecc66161fc93d7c9000da1',
            '0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f',
        ],
        'pulsechain': [
            '0x98bf93ebf5c380c0e6ae8e192a7e2ae08edacc02',
            '0xa1077a294dde1b09bb078844df40758a5d0f9a27',
            '0x0cb6f5a34ad42ec934882a05265a7d5f59b51a2f',
            '0x15d38573d2feeb82e7ad5187ab8c1d52810b1f07',
            '0xb4e16d0168e52d35cacdc2c6185b44281ec28c9dc',
        ],
        'base': [
            '0xfcd3842f85ed87ba2889b4d35893403796e67ff1',
            '0x4200000000000000000000000000000000000006'
        ]
    }
    if chain not in address_dict:
        return []
    return [address.lower() for address in address_dict[chain]]


def get_factory_address(chain):
    chain = chain.lower()
    factory_dict = {
        'mainnet': '0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f',
        'eth': '0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f',
        'bsc': '0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73',
        'polygon': '0x5757371414417b8C6CAad45bAeF941aBc7d3Ab32',
        'avalanche': '0x9Ad6C38BE94206cA50bb0d90783181662f0Cfa10',
        'fantom': '0x152eE697f2E276fA89E96742e9bB9aB1F2E61bE3',
        'arbitrum': '0xc35DADB65012eC5796536bD9864eD8773aBc74C4',
        'pulsechain': '0x1b8E12F839BD4e73A47adDF76cF7F0097d74c14C',
        'base': '0x1b8E12F839BD4e73A47adDF76cF7F0097d74c14C',
        'optimism': '0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f',
    }
    if chain not in factory_dict:
        return None
    return factory_dict[chain]


def get_rpc_endpoints(chain):
    chain = chain.lower()
    rpc_endpoints = {
        'mainnet': 'https://rpc.ankr.com/eth',
        'eth': 'https://rpc.ankr.com/eth',
        'bsc': 'https://rpc.ankr.com/bsc',
        'polygon': 'https://polygon-rpc.com',
        'avalanche': 'https://api.avax.network/ext/bc/C/rpc',
        'fantom': 'https://rpc.fantom.network',
        'arbitrum': 'https://arbitrum.meowrpc.com',
        'pulsechain': 'https://rpc.pulsechain.com',
        'base': 'https://mainnet.base.org',
        'optimism': 'https://mainnet.optimism.io',
        'gnosis': 'https://rpc.gnosischain.com/',
    }
    if chain not in rpc_endpoints:
        return None
    return rpc_endpoints[chain]


def get_function_calls_to_expand():
    return {
        'flashloan': [
            'flashLoan',
            'flashLoanSimple',
            'flashBorrow',
            'dYdXFlashLoan',
            'balancerFlashLoan',
            'flashMint',
            'maxFlashLoan',
            'flashFee',
            'flashRedeem',
            'depositFlashloan',
            'withdrawFlashloan'
        ],
        'callback': [
            'executeOperation',
            'onFlashLoan',
            'DVMFlashLoanCall',
            'DPPFlashLoanCall',
            'onERC3156FlashLoan',
            'executeFlashLoan',
            'onFlashLoanComplete',
            'onFlashLoanStart',
            'uniswapV2Call',
            'swap',
            'execute',
            'callFunction',
            'flashCallback',
            'receiveFlashLoan',
            'onDeferredLiquidityCheck',
            'flashClose',
            'onMorphoFlashLoan'
        ]
    }


def is_function_hash(function_name):
    if not isinstance(function_name, str):
        return False
    if function_name.startswith('0x'):
        function_name = function_name[2:]
    # Allow optional parentheses/arguments after the 8 hex chars
    function_hash_pattern = r'^[0-9a-fA-F]{8}(?:$|\()'
    if re.match(function_hash_pattern, function_name):
        return True
    return False


def build_agent(task, model):
    """Build an agent for `model`, routing cloud models to their provider.

    Previously everything non-GPT fell through to OllmaAgent (local Ollama),
    which silently broke gemini-*/grok-*/qwen-* on hosts without Ollama.
    Delegate to build_provider_agent, which maps provider prefixes to the
    right OpenAI-compatible endpoint and fails fast on unsupported ones.
    """
    from faultseeker.utils.agent import build_provider_agent
    return build_provider_agent(task, model.strip().lower())