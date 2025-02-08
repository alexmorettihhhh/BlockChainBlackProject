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
}

impl BlockchainType {
    fn get_url(&self) -> &str {
        match self {
            BlockchainType::Ethereum => "https://mainnet.infura.io/v3/YOUR_INFURA_KEY",
            BlockchainType::Near => "https://rpc.mainnet.near.org", // Пример для NEAR
        }
    }
}

struct BlockchainClient {
    provider: Provider<Http>,
    contracts: Vec<Address>,
    blockchain_type: BlockchainType,
}

impl BlockchainClient {
    
    fn new(url: &str, blockchain_type: BlockchainType) -> Self {
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

    
    async fn get_balance(&self, address: Address) -> U256 {
        match self.provider.get_balance(address, None).await {
            Ok(balance) => balance,
            Err(e) => {
                error!("Ошибка при получении баланса: {}", e);
                U256::zero()
            }
        }
    }

    
    async fn get_events_from_block(&self, block_number: u64, contract_address: Address) -> Vec<Log> {
        let filter = Filter::new()
            .address(contract_address)
            .from_block(BlockId::Number(BlockNumber::Number(block_number.into())));

        let logs = self.provider.get_logs(&filter).await.unwrap();
        logs
    }

    
    async fn get_contract_data(&self, abi: &[u8], contract_address: Address) -> Result<U256, ContractError> {
        let contract = Contract::from_json(self.provider.clone(), contract_address, abi)?;
        let data: U256 = contract.query("counter", (), None, Options::default(), None).await?;
        Ok(data)
    }

    
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

    
    async fn send_transaction(&self, contract_address: Address, abi: &[u8], from: Address, private_key: &str) -> Result<(), ContractError> {
        let wallet: LocalWallet = private_key.parse().expect("Invalid private key");
        let provider = Provider::<Http>::try_from("https://mainnet.infura.io/v3/YOUR_INFURA_KEY")?.with_sender(wallet.clone());
        
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

    
    async fn subscribe_to_events(&self, contract_address: Address) {
        let filter = Filter::new().address(contract_address).event("CounterIncremented");

        let mut stream = self.provider.watch_logs(&filter).await.unwrap();

        while let Some(log) = stream.next().await {
            let decoded: (U256,) = contract.decode_log(&log).unwrap();
            println!("Получено событие: CounterIncremented с новым значением: {}", decoded.0);
        }
    }

    
    async fn get_contract_owner(&self, contract_address: Address, abi: &[u8]) -> Address {
        let contract = Contract::from_json(self.provider.clone(), contract_address, abi).unwrap();
        let owner: Address = contract.query("owner", (), None, Options::default(), None).await.unwrap();
        owner
    }
}


struct ContractFactory {
    provider: Provider<Http>,
}

impl ContractFactory {
    fn new(url: &str) -> Self {
        ContractFactory {
            provider: Provider::<Http>::try_from(url).expect("Invalid provider"),
        }
    }

    fn create_contract(&self, address: Address, abi: &[u8]) -> Contract<Http> {
        Contract::from_json(self.provider.clone(), address, abi).unwrap()
    }

    fn get_contract_balance(&self, contract: &Contract<Http>) -> U256 {
        contract.query("balance", (), None, Options::default(), None).unwrap()
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
    match env::var("PRIVATE_KEY") {
        Ok(key) => Some(key),
        Err(_) => None,
    }
}

#[tokio::main]
async fn main() {
    env_logger::init(); 

    println!("Выберите операцию:");
    println!("1. Получить баланс");
    println!("2. Отправить транзакцию");
    println!("3. Подписаться на события");

    let mut choice = String::new();
    io::stdin().read_line(&mut choice).expect("Не удалось прочитать строку");

    let url = "https://mainnet.infura.io/v3/YOUR_INFURA_KEY";
    let blockchain_client = BlockchainClient::new(url, BlockchainType::Ethereum);
    let contract_address: Address = "0xYourContractAddress".parse().unwrap();
    let abi = include_bytes!("../path_to_your_contract/contract_abi.json");

    match choice.trim() {
        "1" => {
            
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
            
            blockchain_client.subscribe_to_events(contract_address).await;
        }
        _ => eprintln!("Неверный выбор"),
    }
}
