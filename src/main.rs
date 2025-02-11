use ethers::{
    prelude::*,
    providers::{Http, Provider},
<<<<<<< HEAD
    types::{TransactionRequest, U256, Address, Log, BlockId, BlockNumber, Filter, H256, Transaction},
=======
    types::{TransactionRequest, U256, Address, Log, BlockId, BlockNumber, Filter},
>>>>>>> 903a872d38fc2a10f683a89f681e6de2a3abf619
    contract::{Contract, ContractError},
    middleware::Middleware,
    signers::LocalWallet,
};
<<<<<<< HEAD
use std::collections::HashMap;
use regex::Regex;
use dotenv::dotenv;
use std::env;
use tokio::sync::mpsc;
=======
>>>>>>> 903a872d38fc2a10f683a89f681e6de2a3abf619

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
<<<<<<< HEAD
            BlockchainType::Near => "https://rpc.mainnet.near.org",
            BlockchainType::Polygon => "https://polygon-rpc.com",
            BlockchainType::BSC => "https://bsc-dataseed1.binance.org:443",
            BlockchainType::Avalanche => "https://api.avax.network/ext/bc/C/rpc",
            BlockchainType::Solana => "https://api.mainnet-beta.solana.com",
=======
            BlockchainType::Near => "https://rpc.mainnet.near.org", 
            BlockchainType::Polygon => "https://polygon-rpc.com", 
            BlockchainType::BSC => "https://bsc-dataseed1.binance.org:443", 
            BlockchainType::Avalanche => "https://api.avax.network/ext/bc/C/rpc", 
            BlockchainType::Solana => "https://api.mainnet-beta.solana.com", 
>>>>>>> 903a872d38fc2a10f683a89f681e6de2a3abf619
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
<<<<<<< HEAD
=======
        
>>>>>>> 903a872d38fc2a10f683a89f681e6de2a3abf619
        BlockchainClient {
            provider,
            contracts: Vec::new(),
            blockchain_type,
<<<<<<< HEAD
            cache: HashMap::new(),
        }
    }

=======
        } =
    } =
} =
>>>>>>> 903a872d38fc2a10f683a89f681e6de2a3abf619
    fn add_contract(&mut self, contract_address: Address) {
        self.contracts.push(contract_address);
    }

    fn switch_blockchain(&mut self, new_blockchain_type: BlockchainType) {
        self.blockchain_type = new_blockchain_type;
    }

<<<<<<< HEAD
=======
    fn get_provider(&self) -> &Provider<Http> {
        &self.provider
    }

>>>>>>> 903a872d38fc2a10f683a89f681e6de2a3abf619
    async fn get_balance_ethereum(&self, address: Address) -> U256 {
        match self.provider.get_balance(address, None).await {
            Ok(balance) => balance,
            Err(e) => {
                eprintln!("Ошибка при получении баланса: {}", e);
                U256::zero()
            }
        }
    }

<<<<<<< HEAD
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
=======
    async fn get_balance_sol(&self, address: Address) -> Result<U256, String> {
        // Специфическая логика для получения баланса на Solana
        Err("Не поддерживается для Solana".to_string())
    }

    async fn get_balance(&self, address: Address) -> U256 {
        match self.blockchain_type {
            BlockchainType::Ethereum => self.get_balance_ethereum(address).await,
            BlockchainType::Solana => self.get_balance_sol(address).await.unwrap_or(U256::zero()),
            _ => U256::zero(), // для других блокчейнов пока не реализовано
        }
    }

    async fn get_events_from_block(&self, block_number: u64, contract_address: Address) -> Vec<Log> {
        let filter = Filter::new()
            .address(contract_address)
            .from_block(BlockNumber::Number(block_number.into()));
        
        self.provider.get_logs(&filter).await.unwrap()
    }

    async fn get_contract_data<M>(&self, abi: &[u8], contract_address: Address) -> Result<U256, ContractError<M>>
    where
        M: Middleware,
    {
        let contract = Contract::new(contract_address, abi, self.provider.clone());
        let data: U256 = contract.query("counter", (), None, Default::default(), None).await?; 
        Ok(data)
    }

    async fn get_data_from_multiple_contracts(&self, contracts: Vec<Address>, abi: &[u8]) {
        let tasks: Vec<_> = contracts.into_iter().map(|contract_address| {
            tokio::spawn(self.get_contract_data(abi, contract_address))
        }).collect();

        let results = join_all(tasks).await;
        for result in results {
            match result {
                Ok(data) => println!("Data from contract: {:?}", data),
                Err(e) => eprintln!("Ошибка получения данных с контракта: {}", e),
>>>>>>> 903a872d38fc2a10f683a89f681e6de2a3abf619
            }
        }
    }

<<<<<<< HEAD
    fn export_data_to_file(data: &str, file_name: &str) -> Result<(), std::io::Error> {
        std::fs::write(file_name, data)?;
        println!("Данные успешно экспортированы в файл {}", file_name);
        Ok(())
    }

    fn get_cached_balance(&mut self, address: Address) -> U256 {
        let key = format!("{:?}", address);
        if let Some(balance) = self.cache.get(&key) {
            return *balance;
=======
    async fn send_transaction(&self, contract_address: Address, abi: &[u8], from: Address, private_key: &str) -> Result<(), ContractError<Provider<Http>>> {
        let wallet: LocalWallet = private_key.parse().expect("Invalid private key");
        let client = SignerMiddleware::new(self.provider.clone(), wallet);
        let contract = Contract::new(contract_address, abi, Arc::new(client));
        
        let call = contract.method::<_, ()>("incrementCounter", ())?;
        let tx = call.send().await?;
        
        println!("Transaction hash: {:?}", tx.tx_hash());
        Ok(())
    }

    async fn subscribe_to_events(&self, contract_address: Address) {
        let filter = Filter::new().address(contract_address).event("CounterIncremented");

        let mut stream = self.provider.watch(&filter).await.unwrap();

        while let Some(log) = stream.next().await {
            let decoded: (U256,) = self.provider.decode_log(&log).unwrap();
            println!("Получено событие: CounterIncremented с новым значением: {}", decoded.0);
>>>>>>> 903a872d38fc2a10f683a89f681e6de2a3abf619
        }
        let balance = self.get_balance(address).await;
        self.cache.insert(key, balance);
        balance
    }

<<<<<<< HEAD
    fn get_blockchain_info(&self) -> String {
        format!("Текущий блокчейн: {:?}", self.blockchain_type)
    }

    fn list_contracts(&self) -> Vec<Address> {
        self.contracts.clone()
=======
    async fn get_contract_owner(&self, contract_address: Address, abi: &[u8]) -> Address {
        let contract = Contract::new(contract_address, abi, self.provider.clone());
        let owner: Address = contract.query("owner", (), None, Default::default(), None).await.unwrap();
        owner
>>>>>>> 903a872d38fc2a10f683a89f681e6de2a3abf619
    }

<<<<<<< HEAD
=======
    // Новая функция для получения текущей блокчейн информации
    fn get_blockchain_info(&self) -> String {
        format!("Текущий блокчейн: {:?}", self.blockchain_type)
    }

    // Новая функция для получения списка контрактов
    fn list_contracts(&self) -> Vec<Address> {
        self.contracts.clone()
    }
}

>>>>>>> 903a872d38fc2a10f683a89f681e6de2a3abf619
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
<<<<<<< HEAD
=======
}

#[tokio::main]
async fn main() {
    let mut blockchain_client = BlockchainClient::new(BlockchainType::Ethereum);
    let contract_address: Address = "0xYourContractAddress".parse().unwrap();
    let abi = include_bytes!("../contracts/abi.json");

    loop {
        show_menu();
        let mut choice = String::new();
        io::stdin().read_line(&mut choice).expect("Не удалось прочитать строку");

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
            "4" => {
                println!("Выберите блокчейн (Ethereum, Polygon, BSC, Solana):");
                let mut blockchain_choice = String::new();
                io::stdin().read_line(&mut blockchain_choice).expect("Не удалось прочитать строку");

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
                io::stdin().read_line(&mut addresses_input).expect("Не удалось прочитать строку");

                let contract_addresses: Vec<Address> = addresses_input
                    .trim()
                    .split(',')
                    .filter_map(|addr| addr.parse().ok())
                    .collect();

                blockchain_client.get_data_from_multiple_contracts(contract_addresses, abi).await;
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
>>>>>>> 903a872d38fc2a10f683a89f681e6de2a3abf619
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