use ethers::{
    prelude::*,
    providers::{Http, Provider},
    types::{TransactionRequest, U256, Address, Log, BlockId, BlockNumber, Filter, H256, Transaction},
    contract::{Contract, ContractError},
    middleware::Middleware,
    signers::LocalWallet,
};
use std::collections::HashMap;
use regex::Regex;
use dotenv::dotenv;
use std::env;
use tokio::sync::mpsc;

#[derive(Clone, Serialize, Deserialize, Debug)]
struct Event {
    block_number: u64,
    event_type: String,
    data: String,
}

#[derive(Debug)]
enum BlockchainType {
    Ethereum,
    Near,
    Polygon,
    BSC,
    Avalanche,
    Solana,
}

impl BlockchainType {
    fn get_url(&self) -> &str {
        match self {
            BlockchainType::Ethereum => "https://mainnet.infura.io/v3/YOUR_INFURA_KEY",
            BlockchainType::Near => "https://rpc.mainnet.near.org",
            BlockchainType::Polygon => "https://polygon-rpc.com",
            BlockchainType::BSC => "https://bsc-dataseed1.binance.org:443",
            BlockchainType::Avalanche => "https://api.avax.network/ext/bc/C/rpc",
            BlockchainType::Solana => "https://api.mainnet-beta.solana.com",
        }
    }
}

struct BlockchainClient {
    provider: Provider<Http>,
    contracts: Vec<Address>,
    blockchain_type: BlockchainType,
    cache: HashMap<String, U256>,
}

impl BlockchainClient {
    fn new(blockchain_type: BlockchainType) -> Self {
        let url = blockchain_type.get_url();
        let provider = Provider::new(Http::new(url.parse().unwrap()));
        BlockchainClient {
            provider,
            contracts: Vec::new(),
            blockchain_type,
            cache: HashMap::new(),
        }
    }

    fn add_contract(&mut self, contract_address: Address) {
        self.contracts.push(contract_address);
    }

    fn switch_blockchain(&mut self, new_blockchain_type: BlockchainType) {
        self.blockchain_type = new_blockchain_type;
    }

    async fn get_balance_ethereum(&self, address: Address) -> U256 {
        match self.provider.get_balance(address, None).await {
            Ok(balance) => balance,
            Err(e) => {
                eprintln!("Ошибка при получении баланса: {}", e);
                U256::zero()
            }
        }
    }

    async fn get_balance_sol(&self, _address: Address) -> Result<U256, String> {
        Err("Не поддерживается для Solana".to_string())
    }

    async fn get_balance(&self, address: Address) -> U256 {
        match self.blockchain_type {
            BlockchainType::Ethereum => self.get_balance_ethereum(address).await,
            BlockchainType::Solana => self.get_balance_sol(address).await.unwrap_or(U256::zero()),
            _ => U256::zero(),
        }
    }

    async fn get_transactions_by_address(&self, address: Address) -> Vec<Transaction> {
        let mut transactions = Vec::new();
        let block_number = self.provider.get_block_number().await.unwrap();
        for i in 0..block_number.as_u64() {
            let block = self.provider.get_block(BlockId::Number(i.into())).await.unwrap();
            if let Some(block) = block {
                for tx in block.transactions {
                    if let Transaction::Legacy(tx) = tx {
                        if tx.from == address || tx.to == Some(address) {
                            transactions.push(tx);
                        }
                    }
                }
            }
        }
        transactions
    }

    async fn check_transaction_status(&self, tx_hash: H256) -> String {
        match self.provider.get_transaction_receipt(tx_hash).await {
            Ok(Some(receipt)) => {
                if receipt.status == Some(1.into()) {
                    "Транзакция успешно подтверждена".to_string()
                } else {
                    "Транзакция отклонена".to_string()
                }
            }
            Ok(None) => "Транзакция еще не подтверждена".to_string(),
            Err(_) => "Ошибка при получении статуса транзакции".to_string(),
        }
    }

    async fn get_gas_price(&self) -> U256 {
        match self.provider.get_gas_price().await {
            Ok(price) => price,
            Err(e) => {
                eprintln!("Ошибка при получении газовой цены: {}", e);
                U256::zero()
            }
        }
    }

    fn export_data_to_file(data: &str, file_name: &str) -> Result<(), std::io::Error> {
        std::fs::write(file_name, data)?;
        println!("Данные успешно экспортированы в файл {}", file_name);
        Ok(())
    }

    fn get_cached_balance(&mut self, address: Address) -> U256 {
        let key = format!("{:?}", address);
        if let Some(balance) = self.cache.get(&key) {
            return *balance;
        }
        let balance = self.get_balance(address).await;
        self.cache.insert(key, balance);
        balance
    }

    fn get_blockchain_info(&self) -> String {
        format!("Текущий блокчейн: {:?}", self.blockchain_type)
    }

    fn list_contracts(&self) -> Vec<Address> {
        self.contracts.clone()
    }
}

fn validate_address(address: &str) -> Result<Address, String> {
    let re = Regex::new(r"^0x[a-fA-F0-9]{40}$").unwrap();
    if re.is_match(address) {
        Ok(address.parse().unwrap())
    } else {
        Err("Неверный формат адреса".to_string())
    }
}

fn validate_private_key(private_key: &str) -> Result<String, String> {
    let private_key = private_key.trim();
    if private_key.len() == 66 && private_key.starts_with("0x") {
        Ok(private_key.to_string())
    } else {
        Err("Неверный формат приватного ключа".to_string())
    }
}

fn get_private_key_from_env() -> Option<String> {
    dotenv().ok();
    match env::var("PRIVATE_KEY") {
        Ok(key) => Some(key),
        Err(_) => None,
    }
}

fn send_notification(message: &str) {
    println!("[ALERT] {}", message);
}

fn show_menu() {
    println!("Выберите операцию:");
    println!("1. Получить баланс");
    println!("2. Отправить транзакцию");
    println!("3. Подписаться на события");
    println!("4. Переключить блокчейн");
    println!("5. Работать с несколькими контрактами");
    println!("6. Показать информацию о текущем блокчейне");
    println!("7. Показать все контракты");
    println!("8. Выход");
}

#[tokio::main]
async fn main() {
    let mut blockchain_client = BlockchainClient::new(BlockchainType::Ethereum);
    let contract_address: Address = "0xYourContractAddress".parse().unwrap();
    let abi = include_bytes!("../contracts/abi.json");

    loop {
        show_menu();
        let mut choice = String::new();
        std::io::stdin()
            .read_line(&mut choice)
            .expect("Не удалось прочитать строку");

        match choice.trim() {
            "1" => {
                println!("Введите адрес кошелька:");
                let mut address = String::new();
                std::io::stdin()
                    .read_line(&mut address)
                    .expect("Не удалось прочитать строку");
                match validate_address(address.trim()) {
                    Ok(address) => {
                        let balance = blockchain_client.get_balance(address).await;
                        println!("Баланс: {}", balance);
                    }
                    Err(e) => eprintln!("Ошибка валидации адреса: {}", e),
                }
            }
            "2" => {
                println!("Введите приватный ключ:");
                let mut private_key = String::new();
                std::io::stdin()
                    .read_line(&mut private_key)
                    .expect("Не удалось прочитать строку");
                match validate_private_key(private_key.trim()) {
                    Ok(private_key) => {
                        blockchain_client
                            .send_transaction(contract_address, abi, contract_address, &private_key)
                            .await
                            .unwrap();
                    }
                    Err(e) => eprintln!("Ошибка валидации приватного ключа: {}", e),
                }
            }
            "3" => {
                blockchain_client.subscribe_to_events(contract_address).await;
            }
            "4" => {
                println!("Выберите блокчейн (Ethereum, Polygon, BSC, Solana):");
                let mut blockchain_choice = String::new();
                std::io::stdin()
                    .read_line(&mut blockchain_choice)
                    .expect("Не удалось прочитать строку");
                let new_blockchain = match blockchain_choice.trim() {
                    "Ethereum" => BlockchainType::Ethereum,
                    "Polygon" => BlockchainType::Polygon,
                    "BSC" => BlockchainType::BSC,
                    "Solana" => BlockchainType::Solana,
                    _ => BlockchainType::Ethereum,
                };
                blockchain_client.switch_blockchain(new_blockchain);
                println!("Переключение блокчейна на {:?}", new_blockchain);
            }
            "5" => {
                println!("Введите адреса контрактов через запятую (например, 0xAddress1,0xAddress2):");
                let mut addresses_input = String::new();
                std::io::stdin()
                    .read_line(&mut addresses_input)
                    .expect("Не удалось прочитать строку");
                let contract_addresses: Vec<Address> = addresses_input
                    .trim()
                    .split(',')
                    .filter_map(|addr| addr.parse().ok())
                    .collect();
                blockchain_client
                    .get_data_from_multiple_contracts(contract_addresses, abi)
                    .await;
            }
            "6" => {
                println!("{}", blockchain_client.get_blockchain_info());
            }
            "7" => {
                let contracts = blockchain_client.list_contracts();
                for contract in contracts {
                    println!("Контракт: {:?}", contract);
                }
            }
            "8" => {
                break;
            }
            _ => eprintln!("Неверный выбор"),
        }
    }
}