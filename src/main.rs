use ethers::prelude::*;
use ethers::contract::{Contract, ContractError};
use ethers::types::{TransactionRequest, U256, Address, Log, BlockId, BlockNumber, Options};
use log::{error, info};
use std::sync::Arc;
use tokio::sync::Mutex;
use futures::future::join_all;
use std::io::{self, Write};
use std::env;
use regex::Regex;
use ethers::providers::{Provider, Http}; // Добавляем для работы с провайдерами

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
            BlockchainType::Near => "https://rpc.mainnet.near.org", // Пример для NEAR
            BlockchainType::Polygon => "https://polygon-rpc.com", // RPC URL для Polygon
            BlockchainType::BSC => "https://bsc-dataseed1.binance.org:443", // RPC URL для BSC
            BlockchainType::Avalanche => "https://api.avax.network/ext/bc/C/rpc", // RPC URL для Avalanche
            BlockchainType::Solana => "https://api.mainnet-beta.solana.com", // RPC URL для Solana
        }
    }
}

struct BlockchainClient {
    provider: Provider<Http>,
    contracts: Vec<Address>,
    blockchain_type: BlockchainType,
}

impl BlockchainClient {
    fn new(blockchain_type: BlockchainType) -> Self {
        let url = blockchain_type.get_url();
        let provider = Provider::<Http>::try_from(url).expect("Invalid provider");

        BlockchainClient {
            provider,
            contracts: Vec::new(),
            blockchain_type,
        }
    }

    fn add_contract(&mut self, contract_address: Address) {
        self.contracts.push(contract_address);
    }

    fn switch_blockchain(&mut self, new_blockchain_type: BlockchainType) {
        self.blockchain_type = new_blockchain_type;
    }

    fn get_provider(&self) -> &Provider<Http> {
        &self.provider
    }

    // Получение баланса
    async fn get_balance(&self, address: Address) -> U256 {
        match self.provider.get_balance(address, None).await {
            Ok(balance) => balance,
            Err(e) => {
                error!("Ошибка при получении баланса: {}", e);
                U256::zero()
            }
        }
    }

    // Получение событий из блока
    async fn get_events_from_block(&self, block_number: u64, contract_address: Address) -> Vec<Log> {
        let filter = Filter::new()
            .address(contract_address)
            .from_block(BlockId::Number(BlockNumber::Number(block_number.into())));

        let logs = self.provider.get_logs(&filter).await.unwrap();
        logs
    }

    // Получение данных из контракта
    async fn get_contract_data(&self, abi: &[u8], contract_address: Address) -> Result<U256, ContractError> {
        let contract = Contract::from_json(self.provider.clone(), contract_address, abi)?;
        let data: U256 = contract.query("counter", (), None, Options::default(), None).await?;
        Ok(data)
    }

    // Получение данных из нескольких контрактов
    async fn get_data_from_multiple_contracts(&self, contracts: Vec<Address>, abi: &[u8]) {
        let tasks: Vec<_> = contracts.into_iter().map(|contract_address| {
            tokio::spawn(self.get_contract_data(abi, contract_address))
        }).collect();

        let results = join_all(tasks).await;
        for result in results {
            match result {
                Ok(data) => println!("{:?}", data),
                Err(e) => eprintln!("Ошибка получения данных: {}", e),
            }
        }
    }

    // Отправка транзакции
    async fn send_transaction(&self, contract_address: Address, abi: &[u8], from: Address, private_key: &str) -> Result<(), ContractError> {
        let wallet: LocalWallet = private_key.parse().expect("Invalid private key");
        let provider = self.provider.with_sender(wallet.clone());

        let contract = Contract::from_json(provider.clone(), contract_address, abi)?;

        let tx: TransactionRequest = contract.call("incrementCounter", (), from).await?;

        let pending_tx = provider.send_transaction(tx, None).await?;

        let receipt = pending_tx.confirmations(1).await?;
        if let Some(receipt) = receipt {
            println!("Транзакция успешна, хэш: {:?}", receipt.transaction_hash);
        } else {
            eprintln!("Транзакция не была подтверждена.");
        }

        Ok(())
    }

    // Подписка на события
    async fn subscribe_to_events(&self, contract_address: Address) {
        let filter = Filter::new().address(contract_address).event("CounterIncremented");

        let mut stream = self.provider.watch_logs(&filter).await.unwrap();

        while let Some(log) = stream.next().await {
            let decoded: (U256,) = self.provider.decode_log(&log).unwrap();
            println!("Получено событие: CounterIncremented с новым значением: {}", decoded.0);
        }
    }

    // Получение владельца контракта
    async fn get_contract_owner(&self, contract_address: Address, abi: &[u8]) -> Address {
        let contract = Contract::from_json(self.provider.clone(), contract_address, abi).unwrap();
        let owner: Address = contract.query("owner", (), None, Options::default(), None).await.unwrap();
        owner
    }
}

// Валидация адреса
fn validate_address(address: &str) -> Result<Address, String> {
    let re = Regex::new(r"^0x[a-fA-F0-9]{40}$").unwrap();
    if re.is_match(address) {
        Ok(address.parse().unwrap())
    } else {
        Err("Неверный формат адреса".to_string())
    }
}

// Валидация приватного ключа
fn validate_private_key(private_key: &str) -> Result<String, String> {
    let private_key = private_key.trim();
    if private_key.len() == 66 && private_key.starts_with("0x") {
        Ok(private_key.to_string())
    } else {
        Err("Неверный формат приватного ключа".to_string())
    }
}

// Получение приватного ключа из окружения
fn get_private_key_from_env() -> Option<String> {
    match env::var("PRIVATE_KEY") {
        Ok(key) => Some(key),
        Err(_) => None,
    }
}

#[tokio::main]
async fn main() {
    env_logger::init(); // Инициализация логгера

    println!("Выберите операцию:");
    println!("1. Получить баланс");
    println!("2. Отправить транзакцию");
    println!("3. Подписаться на события");
    println!("4. Переключить блокчейн");

    let mut choice = String::new();
    io::stdin().read_line(&mut choice).expect("Не удалось прочитать строку");

    let mut blockchain_client = BlockchainClient::new(BlockchainType::Ethereum); // Для Ethereum
    let contract_address: Address = "0xYourContractAddress".parse().unwrap();
    let abi = include_bytes!("../path_to_your_contract/contract_abi.json");

    loop {
        match choice.trim() {
            "1" => {
                // Получение баланса
                println!("Введите адрес кошелька:");
                let mut address = String::new();
                io::stdin().read_line(&mut address).expect("Не удалось прочитать строку");

                match validate_address(address.trim()) {
                    Ok(address) => {
                        let balance = blockchain_client.get_balance(address).await;
                        println!("Баланс: {}", balance);
                    }
                    Err(e) => eprintln!("Ошибка валидации адреса: {}", e),
                }
            }
            "2" => {
                // Отправка транзакции
                println!("Введите приватный ключ:");
                let mut private_key = String::new();
                io::stdin().read_line(&mut private_key).expect("Не удалось прочитать строку");

                match validate_private_key(private_key.trim()) {
                    Ok(private_key) => {
                        blockchain_client.send_transaction(contract_address, abi, contract_address, &private_key).await.unwrap();
                    }
                    Err(e) => eprintln!("Ошибка валидации приватного ключа: {}", e),
                }
            }
            "3" => {
                // Подписка на события
                blockchain_client.subscribe_to_events(contract_address).await;
            }
            "4" => {
                println!("Выберите блокчейн (например, Ethereum, Polygon, BSC, Avalanche, Solana):");
                let mut blockchain_choice = String::new();
                io::stdin().read_line(&mut blockchain_choice).expect("Не удалось прочитать строку");

                let new_blockchain = match blockchain_choice.trim() {
                    "Ethereum" => BlockchainType::Ethereum,
                    "Polygon" => BlockchainType::Polygon,
                    "BSC" => BlockchainType::BSC,
                    "Avalanche" => BlockchainType::Avalanche,
                    "Solana" => BlockchainType::Solana,
                    _ => BlockchainType::Ethereum, // По умолчанию Ethereum
                };

                blockchain_client.switch_blockchain(new_blockchain);
                println!("Блокчейн переключен на: {:?}", new_blockchain);
            }
            _ => eprintln!("Неверный выбор"),
        }
    }
}
