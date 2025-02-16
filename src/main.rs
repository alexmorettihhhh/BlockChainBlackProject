extern crate ethers;
extern crate tokio;
extern crate futures;
extern crate serde;
extern crate dotenv;
extern crate regex;

use ethers::{
    prelude::*,
    providers::{Http, Provider},
    types::{TransactionRequest, U256, Address, Log, BlockId, BlockNumber, Filter, H256, Bytes, Transaction, Block, Token},
    contract::{Contract, ContractError, ContractFactory},
    middleware::SignerMiddleware,
    signers::{LocalWallet, Signer},
    core::types::BlockWithTransactions,
};
use std::collections::HashMap;
use regex::Regex;
use dotenv::dotenv;
use std::env;
use tokio::sync::mpsc;
use std::sync::Arc;
use futures::StreamExt;
use serde::{Serialize, Deserialize};
use std::time::Duration;
use log::{info, error, warn};

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
    fn get_url(&self) -> String {
        let infura_key = env::var("INFURA_API_KEY").expect("INFURA_API_KEY must be set");
        match self {
            BlockchainType::Ethereum => format!("https://mainnet.infura.io/v3/{}", infura_key),
            BlockchainType::Near => "https://rpc.mainnet.near.org".to_string(),
            BlockchainType::Polygon => "https://polygon-rpc.com".to_string(),
            BlockchainType::BSC => "https://bsc-dataseed1.binance.org:443".to_string(),
            BlockchainType::Avalanche => "https://api.avax.network/ext/bc/C/rpc".to_string(),
            BlockchainType::Solana => "https://api.mainnet-beta.solana.com".to_string(),
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
        let provider = Provider::<Http>::try_from(url.as_str())
            .expect("could not instantiate HTTP Provider");
        
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

    async fn get_transactions_by_address(&self, address: Address) -> Result<Vec<Transaction>, ContractError> {
        let mut transactions = Vec::new();
        let current_block = self.provider.get_block_number().await?;
        
        for i in 0..current_block.as_u64() {
            if let Some(block) = self.provider.get_block_with_txs(i).await? {
                for tx in block.transactions {
                    if tx.from == address || tx.to == Some(address) {
                        transactions.push(tx);
                    }
                }
            }
        }
        
        Ok(transactions)
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

    async fn get_cached_balance(&mut self, address: Address) -> U256 {
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

    async fn send_transaction(
        &self,
        contract_address: Address,
        abi: &[u8],
        to: Address,
        private_key: &str,
    ) -> Result<H256, ContractError> {
        let wallet = private_key.parse::<LocalWallet>().unwrap();
        let client = SignerMiddleware::new(self.provider.clone(), wallet);
        
        let contract = Contract::new(contract_address, abi.into(), Arc::new(client));
        
        let tx = TransactionRequest::new()
            .to(to)
            .value(U256::from(1000000000000000000u64)) // 1 ETH
            .gas(U256::from(21000));

        let pending_tx = self.provider
            .send_transaction(tx, None)
            .await?;

        Ok(pending_tx.tx_hash())
    }

    async fn subscribe_to_events(&self, contract_address: Address) {
        let filter = Filter::new()
            .address(vec![contract_address])
            .from_block(BlockNumber::Latest);

        let (tx, mut rx) = mpsc::channel(100);

        tokio::spawn(async move {
            while let Some(log) = rx.recv().await {
                let event = Event {
                    block_number: log.block_number.unwrap_or_default().as_u64(),
                    event_type: "Contract Event".to_string(),
                    data: format!("{:?}", log.data),
                };
                println!("Новое событие: {:?}", event);
            }
        });

        if let Ok(mut stream) = self.provider.subscribe_logs(&filter).await {
            while let Some(log) = stream.next().await {
                if let Ok(_) = tx.send(log).await {
                    continue;
                }
            }
        }
    }

    async fn get_data_from_multiple_contracts(
        &self,
        contract_addresses: Vec<Address>,
        abi: &[u8],
    ) -> Result<Vec<(Address, U256)>, ContractError> {
        let mut results = Vec::new();
        
        for address in contract_addresses {
            let contract = Contract::new(
                address,
                abi.into(),
                self.provider.clone(),
            );
            
            // Получаем баланс контракта
            let balance = self.get_balance(address).await;
            results.push((address, balance));
        }
        
        Ok(results)
    }

    async fn get_contract_events(
        &self,
        contract_address: Address,
        from_block: u64,
        to_block: Option<u64>,
    ) -> Result<Vec<Log>, ContractError> {
        let to_block = to_block.map(BlockNumber::Number).unwrap_or(BlockNumber::Latest);
        
        let filter = Filter::new()
            .address(vec![contract_address])
            .from_block(BlockNumber::Number(from_block.into()))
            .to_block(to_block);

        Ok(self.provider.get_logs(&filter).await?)
    }

    async fn estimate_transaction_fee(
        &self,
        to: Address,
        value: U256,
        data: Vec<u8>,
    ) -> Result<U256, ContractError> {
        let gas_price = self.get_gas_price().await;
        let tx = TransactionRequest::new()
            .to(to)
            .value(value)
            .data(data);
            
        let gas_estimate = self.provider.estimate_gas(&tx, None).await?;
        
        Ok(gas_price * gas_estimate)
    }

    async fn get_contract_bytecode(&self, address: Address) -> Result<Bytes, ContractError> {
        Ok(self.provider.get_code(address, None).await?)
    }

    async fn get_token_balance(
        &self,
        token_address: Address,
        wallet_address: Address,
        abi: &[u8],
    ) -> Result<U256, ContractError> {
        let contract = Contract::new(
            token_address,
            abi.into(),
            self.provider.clone(),
        );
        
        let result: U256 = contract
            .method("balanceOf", wallet_address)?
            .call()
            .await?;
            
        Ok(result)
    }

    async fn get_block_info(&self, block_number: Option<u64>) -> Result<Block<H256>, ContractError> {
        let block = match block_number {
            Some(num) => self.provider.get_block(num).await?,
            None => self.provider.get_block(BlockNumber::Latest).await?,
        };
        
        Ok(block.unwrap_or_default())
    }

    async fn get_transaction_history(
        &self,
        address: Address,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<Transaction>, ContractError> {
        let current_block = self.provider.get_block_number().await?.as_u64();
        let from = from_block.unwrap_or(current_block.saturating_sub(1000));
        let to = to_block.unwrap_or(current_block);
        
        let mut transactions = Vec::new();
        
        for block_num in from..=to {
            if let Some(block) = self.provider.get_block_with_txs(block_num).await? {
                for tx in block.transactions {
                    if tx.from == address || tx.to == Some(address) {
                        transactions.push(tx);
                    }
                }
            }
        }
        
        Ok(transactions)
    }

    async fn estimate_erc20_transfer(
        &self,
        token_address: Address,
        to: Address,
        amount: U256,
        abi: &[u8],
    ) -> Result<U256, ContractError> {
        let contract = Contract::new(
            token_address,
            abi.into(),
            self.provider.clone(),
        );
        
        let data = contract
            .encode("transfer", (to, amount))?;
            
        self.estimate_transaction_fee(token_address, U256::zero(), data).await
    }

    async fn get_contract_owner(
        &self,
        contract_address: Address,
        abi: &[u8],
    ) -> Result<Address, ContractError> {
        let contract = Contract::new(
            contract_address,
            abi.into(),
            self.provider.clone(),
        );
        
        let owner: Address = contract
            .method("owner", ())?
            .call()
            .await?;
            
        Ok(owner)
    }

    async fn get_network_stats(&self) -> Result<NetworkStats, ContractError> {
        let current_block = self.provider.get_block_number().await?;
        let gas_price = self.get_gas_price().await;
        let block = self.get_block_info(Some(current_block.as_u64())).await?;
        
        Ok(NetworkStats {
            current_block: current_block.as_u64(),
            gas_price,
            last_block_timestamp: block.timestamp.as_u64(),
            last_block_hash: block.hash.unwrap_or_default(),
            difficulty: block.difficulty,
        })
    }

    async fn validate_contract_interaction(
        &self,
        contract_address: Address,
        abi: &[u8],
        method_name: &str,
        args: Vec<Token>,
    ) -> Result<bool, ContractError> {
        let contract = Contract::new(
            contract_address,
            abi.into(),
            self.provider.clone(),
        );
        
        // Проверяем, существует ли метод в ABI
        if !contract.abi().functions.contains_key(method_name) {
            return Ok(false);
        }
        
        // Пробуем закодировать аргументы
        contract.encode(method_name, args)?;
        
        // Проверяем, что контракт существует
        let code = self.get_contract_bytecode(contract_address).await?;
        if code.is_empty() {
            return Ok(false);
        }
        
        Ok(true)
    }

    async fn decode_transaction_input(
        &self,
        tx_hash: H256,
        abi: &[u8],
    ) -> Result<DecodedTransaction, ContractError> {
        let tx = self.provider.get_transaction(tx_hash).await?
            .ok_or(ContractError::CustomError("Transaction not found".into()))?;
            
        let contract = Contract::new(
            tx.to.unwrap_or_default(),
            abi.into(),
            self.provider.clone(),
        );
        
        let decoded = contract.decode_input(&tx.input)?;
        
        Ok(DecodedTransaction {
            function_name: decoded.0,
            params: decoded.1,
            value: tx.value,
            from: tx.from,
            to: tx.to.unwrap_or_default(),
        })
    }

    async fn get_nft_metadata(
        &self,
        nft_contract: Address,
        token_id: U256,
        abi: &[u8],
    ) -> Result<NFTMetadata, ContractError> {
        let contract = Contract::new(
            nft_contract,
            abi.into(),
            self.provider.clone(),
        );
        
        let uri: String = contract
            .method("tokenURI", token_id)?
            .call()
            .await?;
            
        let owner: Address = contract
            .method("ownerOf", token_id)?
            .call()
            .await?;
            
        Ok(NFTMetadata {
            token_id,
            uri,
            owner,
            contract_address: nft_contract,
        })
    }

    async fn deploy_contract(
        &self,
        bytecode: Bytes,
        abi: &[u8],
        constructor_args: Vec<Token>,
        private_key: &str,
    ) -> Result<(Address, H256), ContractError> {
        let wallet = private_key.parse::<LocalWallet>().unwrap();
        let client = SignerMiddleware::new(self.provider.clone(), wallet);
        
        let factory = ContractFactory::new(
            abi.into(),
            bytecode,
            Arc::new(client),
        );
        
        let deployer = factory.deploy(constructor_args)?;
        let contract = deployer.send().await?;
        
        Ok((contract.address(), contract.deployment_transaction().unwrap().tx_hash()))
    }

    async fn analyze_contract_activity(
        &self,
        contract_address: Address,
        days: u64,
    ) -> Result<ContractAnalytics, ContractError> {
        let current_block = self.provider.get_block_number().await?;
        let blocks_per_day = 7200; // примерно для Ethereum
        let from_block = current_block.as_u64().saturating_sub(blocks_per_day * days);
        
        let filter = Filter::new()
            .address(vec![contract_address])
            .from_block(BlockNumber::Number(from_block.into()));
            
        let logs = self.provider.get_logs(&filter).await?;
        
        let mut unique_users = std::collections::HashSet::new();
        let mut transaction_count = 0;
        let mut total_value = U256::zero();
        
        for log in &logs {
            if let Some(tx) = self.provider.get_transaction(log.transaction_hash.unwrap()).await? {
                unique_users.insert(tx.from);
                if let Some(to) = tx.to {
                    unique_users.insert(to);
                }
                transaction_count += 1;
                total_value += tx.value;
            }
        }
        
        Ok(ContractAnalytics {
            unique_users: unique_users.len() as u64,
            transaction_count,
            total_value,
            event_count: logs.len() as u64,
            time_period_days: days,
        })
    }

    async fn monitor_gas_prices(&self) -> Result<GasAnalytics, ContractError> {
        let mut readings = Vec::new();
        let interval = Duration::from_secs(12); // каждый блок
        let samples = 10;
        
        for _ in 0..samples {
            let price = self.get_gas_price().await;
            readings.push(price);
            tokio::time::sleep(interval).await;
        }
        
        let avg = readings.iter().sum::<U256>() / U256::from(readings.len());
        let max = readings.iter().max().cloned().unwrap_or_default();
        let min = readings.iter().min().cloned().unwrap_or_default();
        
        Ok(GasAnalytics {
            current: readings.last().cloned().unwrap_or_default(),
            average: avg,
            maximum: max,
            minimum: min,
            sample_count: samples,
        })
    }

    async fn batch_transfer_tokens(
        &self,
        token_address: Address,
        recipients: Vec<(Address, U256)>,
        abi: &[u8],
        private_key: &str,
    ) -> Result<Vec<H256>, ContractError> {
        let wallet = private_key.parse::<LocalWallet>().unwrap();
        let client = SignerMiddleware::new(self.provider.clone(), wallet);
        
        let contract = Contract::new(
            token_address,
            abi.into(),
            Arc::new(client),
        );
        
        let mut transaction_hashes = Vec::new();
        
        for (recipient, amount) in recipients {
            let tx = contract
                .method("transfer", (recipient, amount))?
                .send()
                .await?;
                
            transaction_hashes.push(tx.tx_hash());
        }
        
        Ok(transaction_hashes)
    }

    async fn get_token_holders(
        &self,
        token_address: Address,
        abi: &[u8],
    ) -> Result<Vec<TokenHolder>, ContractError> {
        let transfer_filter = Filter::new()
            .address(vec![token_address])
            .event("Transfer");
            
        let logs = self.provider.get_logs(&transfer_filter).await?;
        let mut holders = std::collections::HashMap::new();
        
        for log in logs {
            if let Ok(decoded) = self.decode_transfer_event(&log) {
                *holders.entry(decoded.to).or_insert(U256::zero()) += decoded.value;
                if decoded.from != Address::zero() {
                    *holders.entry(decoded.from).or_insert(U256::zero()) -= decoded.value;
                }
            }
        }
        
        Ok(holders
            .into_iter()
            .filter(|(_, balance)| *balance > U256::zero())
            .map(|(address, balance)| TokenHolder { address, balance })
            .collect())
    }

    fn decode_transfer_event(&self, log: &Log) -> Result<TransferEvent, ContractError> {
        let topics = log.topics.clone();
        if topics.len() != 3 {
            return Err(ContractError::CustomError("Invalid number of topics".into()));
        }

        Ok(TransferEvent {
            from: Address::from_slice(&topics[1].as_fixed_bytes()[12..]),
            to: Address::from_slice(&topics[2].as_fixed_bytes()[12..]),
            value: U256::from_big_endian(&log.data),
        })
    }
}

#[derive(Debug)]
struct NetworkStats {
    current_block: u64,
    gas_price: U256,
    last_block_timestamp: u64,
    last_block_hash: H256,
    difficulty: U256,
}

#[derive(Debug)]
struct DecodedTransaction {
    function_name: String,
    params: Vec<Token>,
    value: U256,
    from: Address,
    to: Address,
}

#[derive(Debug)]
struct NFTMetadata {
    token_id: U256,
    uri: String,
    owner: Address,
    contract_address: Address,
}

#[derive(Debug)]
struct ContractAnalytics {
    unique_users: u64,
    transaction_count: u64,
    total_value: U256,
    event_count: u64,
    time_period_days: u64,
}

#[derive(Debug)]
struct GasAnalytics {
    current: U256,
    average: U256,
    maximum: U256,
    minimum: U256,
    sample_count: u32,
}

#[derive(Debug)]
struct TokenHolder {
    address: Address,
    balance: U256,
}

#[derive(Debug)]
struct TransferEvent {
    from: Address,
    to: Address,
    value: U256,
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
    println!("8. Получить баланс токена ERC20");
    println!("9. Получить историю транзакций");
    println!("10. Информация о сети");
    println!("11. Декодировать транзакцию");
    println!("12. Оценить стоимость перевода токенов");
    println!("13. Получить метаданные NFT");
    println!("14. Развернуть новый контракт");
    println!("15. Анализ активности контракта");
    println!("16. Мониторинг цен на газ");
    println!("17. Массовый перевод токенов");
    println!("18. Анализ держателей токенов");
    println!("19. Выход");
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    dotenv().ok();
    
    let infura_key = env::var("INFURA_API_KEY").expect("INFURA_API_KEY must be set");
    info!("Starting blockchain client with Infura key: {}", infura_key);
    
    let mut blockchain_client = BlockchainClient::new(BlockchainType::Ethereum);
    let contract_address: Address = "0xYourContractAddress".parse()?;
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
                        match blockchain_client
                            .send_transaction(contract_address, abi, contract_address, &private_key)
                            .await
                        {
                            Ok(tx_hash) => println!("Транзакция отправлена. Hash: {:?}", tx_hash),
                            Err(e) => eprintln!("Ошибка при отправке транзакции: {}", e),
                        }
                    }
                    Err(e) => eprintln!("Ошибка валидации приватного ключа: {}", e),
                }
            }
            "3" => {
                blockchain_client.subscribe_to_events(contract_address).await;
                println!("Подписка на события активирована");
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
                
                match blockchain_client
                    .get_data_from_multiple_contracts(contract_addresses, abi)
                    .await
                {
                    Ok(results) => {
                        for (address, balance) in results {
                            println!("Контракт {:?}: Баланс {}", address, balance);
                        }
                    }
                    Err(e) => eprintln!("Ошибка при получении данных: {}", e),
                }
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
                println!("Введите адрес токена ERC20:");
                let mut token_address = String::new();
                std::io::stdin()
                    .read_line(&mut token_address)
                    .expect("Не удалось прочитать строку");
                match validate_address(token_address.trim()) {
                    Ok(token_address) => {
                        println!("Введите адрес кошелька:");
                        let mut wallet_address = String::new();
                        std::io::stdin()
                            .read_line(&mut wallet_address)
                            .expect("Не удалось прочитать строку");
                        match validate_address(wallet_address.trim()) {
                            Ok(wallet_address) => {
                                match blockchain_client.get_token_balance(token_address, wallet_address, abi) {
                                    Ok(balance) => println!("Баланс токена: {}", balance),
                                    Err(e) => eprintln!("Ошибка при получении баланса токена: {}", e),
                                }
                            }
                            Err(e) => eprintln!("Ошибка валидации адреса токена: {}", e),
                        }
                    }
                    Err(e) => eprintln!("Ошибка валидации адреса токена: {}", e),
                }
            }
            "9" => {
                println!("Введите адрес кошелька:");
                let mut address = String::new();
                std::io::stdin()
                    .read_line(&mut address)
                    .expect("Не удалось прочитать строку");
                match validate_address(address.trim()) {
                    Ok(address) => {
                        match blockchain_client.get_transaction_history(address, None, None) {
                            Ok(transactions) => {
                                for tx in transactions {
                                    println!("Транзакция: {:?}", tx);
                                }
                            }
                            Err(e) => eprintln!("Ошибка при получении истории транзакций: {}", e),
                        }
                    }
                    Err(e) => eprintln!("Ошибка валидации адреса: {}", e),
                }
            }
            "10" => {
                match blockchain_client.get_network_stats().await {
                    Ok(stats) => {
                        println!("Информация о сети:");
                        println!("Текущий блок: {}", stats.current_block);
                        println!("Цена газа: {}", stats.gas_price);
                        println!("Время последнего блока: {}", stats.last_block_timestamp);
                        println!("Хэш последнего блока: {}", stats.last_block_hash);
                        println!("Сложность: {}", stats.difficulty);
                    }
                    Err(e) => eprintln!("Ошибка при получении информации о сети: {}", e),
                }
            }
            "11" => {
                println!("Введите хэш транзакции:");
                let mut tx_hash = String::new();
                std::io::stdin()
                    .read_line(&mut tx_hash)
                    .expect("Не удалось прочитать строку");
                match validate_address(tx_hash.trim()) {
                    Ok(tx_hash) => {
                        match blockchain_client.decode_transaction_input(tx_hash, abi) {
                            Ok(decoded_tx) => {
                                println!("Декодированная транзакция:");
                                println!("Имя функции: {}", decoded_tx.function_name);
                                println!("Параметры: {:?}", decoded_tx.params);
                                println!("Значение: {}", decoded_tx.value);
                                println!("От: {:?}", decoded_tx.from);
                                println!("До: {:?}", decoded_tx.to);
                            }
                            Err(e) => eprintln!("Ошибка при декодировании транзакции: {}", e),
                        }
                    }
                    Err(e) => eprintln!("Ошибка валидации хэша транзакции: {}", e),
                }
            }
            "12" => {
                println!("Введите адрес токена ERC20:");
                let mut token_address = String::new();
                std::io::stdin()
                    .read_line(&mut token_address)
                    .expect("Не удалось прочитать строку");
                match validate_address(token_address.trim()) {
                    Ok(token_address) => {
                        println!("Введите адрес получателя:");
                        let mut to_address = String::new();
                        std::io::stdin()
                            .read_line(&mut to_address)
                            .expect("Не удалось прочитать строку");
                        match validate_address(to_address.trim()) {
                            Ok(to_address) => {
                                match blockchain_client.estimate_erc20_transfer(token_address, to_address, U256::zero(), abi) {
                                    Ok(estimated_fee) => println!("Оценка стоимости перевода: {}", estimated_fee),
                                    Err(e) => eprintln!("Ошибка при оценке стоимости перевода: {}", e),
                                }
                            }
                            Err(e) => eprintln!("Ошибка валидации адреса получателя: {}", e),
                        }
                    }
                    Err(e) => eprintln!("Ошибка валидации адреса токена: {}", e),
                }
            }
            "13" => {
                println!("Введите адрес контракта NFT:");
                let mut nft_contract = String::new();
                std::io::stdin()
                    .read_line(&mut nft_contract)
                    .expect("Не удалось прочитать строку");
                let nft_contract: Address = nft_contract.trim().parse().unwrap();

                println!("Введите ID токена:");
                let mut token_id = String::new();
                std::io::stdin()
                    .read_line(&mut token_id)
                    .expect("Не удалось прочитать строку");
                let token_id: U256 = token_id.trim().parse().unwrap();

                match blockchain_client.get_nft_metadata(nft_contract, token_id, abi) {
                    Ok(metadata) => {
                        println!("Метаданные токена:");
                        println!("ID токена: {}", metadata.token_id);
                        println!("URI токена: {}", metadata.uri);
                        println!("Владелец токена: {:?}", metadata.owner);
                        println!("Адрес контракта: {:?}", metadata.contract_address);
                    }
                    Err(e) => eprintln!("Ошибка при получении метаданных токена: {}", e),
                }
            }
            "14" => {
                println!("Введите байткод контракта:");
                let mut bytecode = String::new();
                std::io::stdin()
                    .read_line(&mut bytecode)
                    .expect("Не удалось прочитать строку");
                let bytecode: Bytes = bytecode.trim().parse().unwrap();

                println!("Введите ABI контракта:");
                let mut abi_input = String::new();
                std::io::stdin()
                    .read_line(&mut abi_input)
                    .expect("Не удалось прочитать строку");
                let abi: Vec<u8> = abi_input.trim().split(',').map(|s| s.parse().unwrap()).collect();

                println!("Введите аргументы конструктора (через запятую):");
                let mut constructor_args = String::new();
                std::io::stdin()
                    .read_line(&mut constructor_args)
                    .expect("Не удалось прочитать строку");
                let constructor_args: Vec<Token> = constructor_args.trim().split(',').map(|s| s.parse().unwrap()).collect();

                println!("Введите приватный ключ:");
                let mut private_key = String::new();
                std::io::stdin()
                    .read_line(&mut private_key)
                    .expect("Не удалось прочитать строку");
                match validate_private_key(private_key.trim()) {
                    Ok(private_key) => {
                        match blockchain_client.deploy_contract(bytecode, &abi, constructor_args, &private_key) {
                            Ok((contract_address, tx_hash)) => {
                                println!("Контракт успешно развернут. Адрес: {:?}", contract_address);
                                println!("Хэш транзакции: {:?}", tx_hash);
                            }
                            Err(e) => eprintln!("Ошибка при развертывании контракта: {}", e),
                        }
                    }
                    Err(e) => eprintln!("Ошибка валидации приватного ключа: {}", e),
                }
            }
            "15" => {
                println!("Введите адрес контракта:");
                let mut contract_address = String::new();
                std::io::stdin()
                    .read_line(&mut contract_address)
                    .expect("Не удалось прочитать строку");
                let contract_address: Address = contract_address.trim().parse().unwrap();

                println!("Введите количество дней:");
                let mut days = String::new();
                std::io::stdin()
                    .read_line(&mut days)
                    .expect("Не удалось прочитать строку");
                let days: u64 = days.trim().parse().unwrap();

                match blockchain_client.analyze_contract_activity(contract_address, days) {
                    Ok(analytics) => {
                        println!("Анализ активности контракта:");
                        println!("Уникальные пользователи: {}", analytics.unique_users);
                        println!("Количество транзакций: {}", analytics.transaction_count);
                        println!("Общая стоимость: {}", analytics.total_value);
                        println!("Количество событий: {}", analytics.event_count);
                        println!("Период времени: {} дней", analytics.time_period_days);
                    }
                    Err(e) => eprintln!("Ошибка при анализе активности контракта: {}", e),
                }
            }
            "16" => {
                match blockchain_client.monitor_gas_prices() {
                    Ok(analytics) => {
                        println!("Мониторинг цен на газ:");
                        println!("Текущая цена: {}", analytics.current);
                        println!("Средняя цена: {}", analytics.average);
                        println!("Максимальная цена: {}", analytics.maximum);
                        println!("Минимальная цена: {}", analytics.minimum);
                        println!("Количество образцов: {}", analytics.sample_count);
                    }
                    Err(e) => eprintln!("Ошибка при мониторинге цен на газ: {}", e),
                }
            }
            "17" => {
                println!("Введите адрес токена ERC20:");
                let mut token_address = String::new();
                std::io::stdin()
                    .read_line(&mut token_address)
                    .expect("Не удалось прочитать строку");
                match validate_address(token_address.trim()) {
                    Ok(token_address) => {
                        println!("Введите получателей (адрес, количество) через запятую (например, 0xRecipient1,100,0xRecipient2,50):");
                        let mut recipients_input = String::new();
                        std::io::stdin()
                            .read_line(&mut recipients_input)
                            .expect("Не удалось прочитать строку");
                        let recipients: Vec<(Address, U256)> = recipients_input
                            .trim()
                            .split(',')
                            .map(|s| {
                                let parts: Vec<&str> = s.split(' ').collect();
                                let address: Address = parts[0].parse().unwrap();
                                let amount: U256 = parts[1].parse().unwrap();
                                (address, amount)
                            })
                            .collect();
                        
                        println!("Введите приватный ключ:");
                        let mut private_key = String::new();
                        std::io::stdin()
                            .read_line(&mut private_key)
                            .expect("Не удалось прочитать строку");
                        match validate_private_key(private_key.trim()) {
                            Ok(private_key) => {
                                match blockchain_client.batch_transfer_tokens(token_address, recipients, abi, &private_key) {
                                    Ok(transaction_hashes) => {
                                        println!("Транзакции успешно отправлены. Хеши:");
                                        for hash in transaction_hashes {
                                            println!("{:?}", hash);
                                        }
                                    }
                                    Err(e) => eprintln!("Ошибка при массовом переводе токенов: {}", e),
                                }
                            }
                            Err(e) => eprintln!("Ошибка валидации приватного ключа: {}", e),
                        }
                    }
                    Err(e) => eprintln!("Ошибка валидации адреса токена: {}", e),
                }
            }
            "18" => {
                println!("Введите адрес токена ERC20:");
                let mut token_address = String::new();
                std::io::stdin()
                    .read_line(&mut token_address)
                    .expect("Не удалось прочитать строку");
                match validate_address(token_address.trim()) {
                    Ok(token_address) => {
                        match blockchain_client.get_token_holders(token_address, abi) {
                            Ok(holders) => {
                                println!("Держатели токена:");
                                for holder in holders {
                                    println!("Адрес: {:?}, Баланс: {}", holder.address, holder.balance);
                                }
                            }
                            Err(e) => eprintln!("Ошибка при получении держателей токена: {}", e),
                        }
                    }
                    Err(e) => eprintln!("Ошибка валидации адреса токена: {}", e),
                }
            }
            "19" => {
                break;
            }
            _ => eprintln!("Неверный выбор"),
        }
    }
    Ok(())
}
