import os
import logging
import json
import shutil
from faultseeker.utils.solidityParser.loc_parser import get_loc_info
from faultseeker.utils.explorer_provider import explorer_call, print_explorer_stats
from dotenv import load_dotenv
load_dotenv(override=True)


LOGGGING_FILE_PATH = './logs/get_source_code.log'
os.makedirs(os.path.dirname(LOGGGING_FILE_PATH), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename=LOGGGING_FILE_PATH, filemode='w'
)

CONTRACT_SOURCES = {
    'eth': 'https://etherscan.io/contractsverified',
    'bsc': 'https://bscscan.com/contractsverified',
    'poly': 'https://polygonscan.com/contractsverified',
    'fantom': 'https://ftmscan.com/contractsverified',
    'arbi': 'https://arbiscan.io/contractsverified',
    'avax': 'https://snowtrace.io/contractsverified',
    'opt': 'https://optimistic.etherscan.io/contractsverified',
    'base': 'https://basescan.org/contractsverified',
    'zksync': 'https://explorer.zksync.io/contractsverified',
    'linea': 'https://lineascan.build/contractsverified',
    'scroll': 'https://scrollscan.com/contractsverified',
    'gnosis': 'https://gnosisscan.io/contractsverified',
    'celo': 'https://celoscan.io/contractsverified',
    'cronos': 'https://cronoscan.com/contractsverified',
    'moonbeam': 'https://moonscan.io/contractsverified',
}


class ContractDownloader:

    def __init__(self, chain: str, address: list,
                 output_dir: str = './temp2',
                 cache_dir: str = './data/cache/contracts'):
        self.chain = chain.lower()
        self.address = address
        self.output_dir = output_dir
        self.cache_dir = cache_dir
        os.makedirs(self.cache_dir, exist_ok=True)

    @staticmethod
    def get_source_code(chain, address, output_dir):
        """Download contract source code via block explorer API (adaptive failover)."""
        os.makedirs(output_dir, exist_ok=True)
        data = explorer_call(chain, {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address,
        })
        if not data or data.get('status') != '1' or not data.get('result'):
            logging.warning(f'No source for {address}[{chain}]: {data.get("message") if data else "all endpoints failed"}')
            return

        result = data['result'][0]
        source_code   = result.get('SourceCode', '')
        contract_name = result.get('ContractName', 'Contract') or 'Contract'

        if not source_code:
            return

        # Handle multi-file source (JSON format wrapped in {{ }})
        if source_code.startswith('{{'):
            try:
                inner = json.loads(source_code[1:-1])
                sources = inner.get('sources', {})
                for path, content in sources.items():
                    safe_name = os.path.basename(path.replace('/', '_'))
                    impl_dir  = os.path.join(output_dir, 'Implementation')
                    os.makedirs(impl_dir, exist_ok=True)
                    with open(os.path.join(impl_dir, safe_name), 'w', encoding='utf-8') as f:
                        f.write(content.get('content', ''))
                return
            except Exception:
                pass

        # Single file source
        impl_dir = os.path.join(output_dir, 'Implementation')
        os.makedirs(impl_dir, exist_ok=True)
        out_file = os.path.join(impl_dir, f'{contract_name}.sol')
        with open(out_file, 'w', encoding='utf-8') as f:
            f.write(source_code)
        logging.info(f'Downloaded {address}[{chain}] -> {out_file}')

    @staticmethod
    def get_source_bundle(chain: str, address: str) -> dict | None:
        """Fetch verified source + ABI for one address in a single explorer call.

        Returns {'contract_name', 'abi', 'proxy', 'sources': {path: content}}
        or None when retrieval fails. A failed call never looks like an empty
        success: None is returned and the primary error is logged.
        """
        data = explorer_call(chain, {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address,
        })
        if not data or data.get('status') != '1' or not data.get('result'):
            logging.warning(
                f'No source bundle for {address}[{chain}]: '
                f'{data.get("message") if data else "all endpoints failed"} '
                f'{data.get("result") if data else ""}'.strip())
            return None
        result = data['result'][0]
        source_code = result.get('SourceCode', '') or ''
        if not source_code.strip():
            logging.warning(f'Empty source for {address}[{chain}] (unverified?)')
            return None

        abi = None
        raw_abi = result.get('ABI')
        if isinstance(raw_abi, str) and raw_abi and raw_abi != 'Contract source code not verified':
            try:
                abi = json.loads(raw_abi)
            except Exception:
                abi = None

        sources = {}
        contract_name = result.get('ContractName', '') or ''
        if source_code.startswith('{{'):
            # Etherscan multi-file standard-json (double-braced)
            try:
                inner = json.loads(source_code[1:-1])
                for path, content in (inner.get('sources', {}) or {}).items():
                    sources[path] = (content or {}).get('content', '')
            except Exception:
                logging.warning(f'Malformed multi-file source for {address}[{chain}]')
                return None
        else:
            fname = result.get('FileName') or f'{contract_name or "Contract"}.sol'
            sources[fname] = source_code
            for extra in (result.get('AdditionalSources') or []):
                if isinstance(extra, dict) and extra.get('SourceCode'):
                    sources[extra.get('Filename') or f'extra_{len(sources)}.sol'] = extra['SourceCode']

        proxy = str(result.get('Proxy', '0')) == '1' or bool(result.get('Implementation'))
        return {
            'contract_name': contract_name,
            'abi': abi,
            'proxy': proxy,
            'sources': sources,
        }

    @staticmethod
    def get_abi(chain: str, address: str) -> list | None:
        """Fetch ABI for a verified contract. Returns parsed list or None."""
        data = explorer_call(chain, {
            'module': 'contract',
            'action': 'getabi',
            'address': address,
        })
        if not data or data.get('status') != '1':
            return None
        try:
            return json.loads(data['result'])
        except Exception:
            return None

    @staticmethod
    def get_internal_txns(chain: str, txn_hash: str) -> list:
        """Fetch internal transactions for a hash (lightweight trace proxy)."""
        data = explorer_call(chain, {
            'module': 'account',
            'action': 'txlistinternal',
            'txhash': txn_hash,
            'sort':   'asc',
        })
        if not data or data.get('status') != '1':
            return []
        return data.get('result', [])



    def process_log(chain, address, output_root):
        f = open(LOGGGING_FILE_PATH, 'r')
        lines = f.readlines()
        f.close()
        output = []
        temp_output = ""

        # split the log file based on projects
        for line in lines:
            if "==========================================" in line:
                if temp_output != "":
                    output.append(temp_output)
                temp_output = ""
            else:
                temp_output += line
        
        # find projects with implementations
        implementations = {}
        for content in output:
            if f'{address}[{chain}]' in content:
                if 'Implementation/' in content:
                    content_lines = content.split('\n')
                    project_name = content_lines[0].split(' - ')[-1]
                    for line in content_lines:
                        path = line.split(' ')[-1].strip()
                        if 'Implementation/' in line:
                            if project_name not in implementations:
                                implementations[project_name] = [path]
                            else:
                                implementations[project_name].append(path)
            
        
        # save implementation to respective project dir
        for project_name in implementations:
            # temp = project_name.split('[')
            # address_temp = temp[0].strip()
            # chain_temp = temp[1].replace(']','').strip()
            project_dir = os.path.join(output_root, 'Implementation')
            os.makedirs(project_dir, exist_ok=True)
            for path in implementations[project_name]:
                # copy the file to project dir
                try:
                    shutil.copy(path, project_dir)
                except Exception:
                    # traceback.print_exc()
                    pass
             
    @staticmethod
    def parse_contract(output_dir):
        output = {}
        for root,_, files in os.walk(output_dir):
            for file in files:
                if file.endswith('.sol'):
                    content = open(os.path.join(root, file), 'r', encoding='utf-8').read()
                    lines = content.split('\n')
                    result = get_loc_info(content)
                    for contract in result:
                        for function in result[contract]['functions']:
                            loc = result[contract]['functions'][function]
                            function_content = '\n'.join(lines[loc['start_line']-1:loc['end_line']])
                            info = {
                                'path':os.path.join(root,file).replace(output_dir,'.'),
                                'start_line':loc['start_line'],
                                'end_line':loc['end_line'],
                                'content':function_content
                            }
                            if function not in output:
                                output[function] = []
                            output[function].append(info)
        return output
    
    def run(self):
        output = {}
        for address in self.address:
            path = os.path.join(self.cache_dir, f'{address.lower()}_{self.chain}.json')
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f:
                    output[address.lower()] = json.load(f)
            else:
                self.get_source_code(self.chain, address, self.output_dir)
                # self.process_log(self.chain, address, self.output_dir)
                data = self.parse_contract(self.output_dir)
                if data:
                    with open(os.path.join(self.cache_dir, f'{address.lower()}_{self.chain}.json'), 'w') as f:
                        json.dump(data, f, indent=4)
                if os.path.exists(self.output_dir):
                    try:
                        shutil.rmtree(self.output_dir)
                    except Exception:
                        continue
                if os.path.exists('./Implementation'):
                    shutil.rmtree('./Implementation')
                output[address.lower()] = data
        return output

if __name__ == '__main__':
    ContractDownloader('bsc','0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c').run()
