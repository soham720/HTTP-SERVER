use axum::{
    extract::Json,
    http::StatusCode,
    response::Json as ResponseJson,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    system_instruction,
    system_program,
};
use solana_sdk::signature::{Keypair, Signature, Signer};
use spl_token::instruction as token_instruction;
use spl_associated_token_account::{instruction as ata_instruction, get_associated_token_address};
use std::str::FromStr;
use ed25519_dalek::{Signature as Ed25519Signature, Signer as Ed25519Signer, Keypair as Ed25519Keypair, PublicKey, Verifier};
use rand::rngs::OsRng;
use base64;
use bs58;

#[derive(Serialize)]
struct SuccessResponse<T> {
    success: bool,
    data: T,
}

#[derive(Serialize)]
struct ErrorResponse {
    success: bool,
    error: String,
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

#[derive(Serialize)]
struct AccountMetaData {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
    #[serde(rename = "isWritable")]
    is_writable: bool,
}

#[derive(Serialize)]
struct InstructionData {
    program_id: String,
    accounts: Vec<AccountMetaData>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SignatureData {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Serialize)]
struct VerifyData {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Serialize)]
struct SolTransferData {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Serialize)]
struct TokenTransferAccount {
    pubkey: String,
    #[serde(rename = "isSigner")]
    is_signer: bool,
}

#[derive(Serialize)]
struct TokenTransferData {
    program_id: String,
    accounts: Vec<TokenTransferAccount>,
    instruction_data: String,
}

fn create_error_response(message: &str) -> (StatusCode, ResponseJson<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        ResponseJson(ErrorResponse {
            success: false,
            error: message.to_string(),
        }),
    )
}

fn validate_pubkey(pubkey_str: &str) -> Result<Pubkey, String> {
    Pubkey::from_str(pubkey_str).map_err(|_| "Invalid public key format".to_string())
}

fn validate_secret_key(secret_str: &str) -> Result<[u8; 64], String> {
    let decoded = bs58::decode(secret_str)
        .into_vec()
        .map_err(|_| "Invalid secret key format")?;
    if decoded.len() != 64 {
        return Err("Invalid secret key length".to_string());
    }
    let mut secret = [0u8; 64];
    secret.copy_from_slice(&decoded);
    Ok(secret)
}

async fn generate_keypair() -> ResponseJson<SuccessResponse<KeypairData>> {
    let keypair = Keypair::new();
    let pubkey = keypair.pubkey().to_string();
    let secret = bs58::encode(&keypair.to_bytes()).into_string();
    ResponseJson(SuccessResponse {
        success: true,
        data: KeypairData { pubkey, secret },
    })
}

async fn create_token(Json(payload): Json<CreateTokenRequest>)
    -> Result<ResponseJson<SuccessResponse<InstructionData>>, (StatusCode, ResponseJson<ErrorResponse>)>
{
    let mint_authority = validate_pubkey(&payload.mint_authority)
        .map_err(|e| create_error_response(&e))?;
    let mint = validate_pubkey(&payload.mint)
        .map_err(|e| create_error_response(&e))?;

    let instruction = token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        Some(&mint_authority),
        payload.decimals,
    ).map_err(|_| create_error_response("Failed to create mint instruction"))?;

    let accounts = instruction.accounts.iter().map(|acc| AccountMetaData {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
        is_writable: acc.is_writable,
    }).collect();

    Ok(ResponseJson(SuccessResponse {
        success: true,
        data: InstructionData {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: base64::encode(&instruction.data),
        },
    }))
}

async fn mint_token(Json(payload): Json<MintTokenRequest>)
    -> Result<ResponseJson<SuccessResponse<InstructionData>>, (StatusCode, ResponseJson<ErrorResponse>)>
{
    let mint = validate_pubkey(&payload.mint).map_err(|e| create_error_response(&e))?;
    let destination = validate_pubkey(&payload.destination).map_err(|e| create_error_response(&e))?;
    let authority = validate_pubkey(&payload.authority).map_err(|e| create_error_response(&e))?;

    let instruction = token_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        payload.amount,
    ).map_err(|_| create_error_response("Failed to create mint instruction"))?;

    let accounts = instruction.accounts.iter().map(|acc| AccountMetaData {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
        is_writable: acc.is_writable,
    }).collect();

    Ok(ResponseJson(SuccessResponse {
        success: true,
        data: InstructionData {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: base64::encode(&instruction.data),
        },
    }))
}

async fn sign_message(Json(payload): Json<SignMessageRequest>)
    -> Result<ResponseJson<SuccessResponse<SignatureData>>, (StatusCode, ResponseJson<ErrorResponse>)>
{
    if payload.message.is_empty() || payload.secret.is_empty() {
        return Err(create_error_response("Missing required fields"));
    }

    let secret_bytes = validate_secret_key(&payload.secret).map_err(|e| create_error_response(&e))?;
    let keypair = Ed25519Keypair::from_bytes(&secret_bytes).map_err(|_| create_error_response("Invalid secret key"))?;
    let signature = keypair.sign(payload.message.as_bytes());

    Ok(ResponseJson(SuccessResponse {
        success: true,
        data: SignatureData {
            signature: base64::encode(signature.to_bytes()),
            public_key: bs58::encode(keypair.public.to_bytes()).into_string(),
            message: payload.message,
        },
    }))
}

async fn verify_message(Json(payload): Json<VerifyMessageRequest>)
    -> Result<ResponseJson<SuccessResponse<VerifyData>>, (StatusCode, ResponseJson<ErrorResponse>)>
{
    if payload.message.is_empty() || payload.signature.is_empty() || payload.pubkey.is_empty() {
        return Err(create_error_response("Missing required fields"));
    }

    let signature_bytes = base64::decode(&payload.signature).map_err(|_| create_error_response("Invalid signature format"))?;
    let pubkey_bytes = bs58::decode(&payload.pubkey).into_vec().map_err(|_| create_error_response("Invalid public key format"))?;
    if pubkey_bytes.len() != 32 {
        return Err(create_error_response("Invalid public key length"));
    }

    let mut pubkey_array = [0u8; 32];
    pubkey_array.copy_from_slice(&pubkey_bytes);
    let public_key = PublicKey::from_bytes(&pubkey_array).map_err(|_| create_error_response("Invalid public key"))?;
    let signature = Ed25519Signature::from_bytes(&signature_bytes).map_err(|_| create_error_response("Invalid signature"))?;
    let valid = public_key.verify(payload.message.as_bytes(), &signature).is_ok();

    Ok(ResponseJson(SuccessResponse {
        success: true,
        data: VerifyData {
            valid,
            message: payload.message,
            pubkey: payload.pubkey,
        },
    }))
}

async fn send_sol(Json(payload): Json<SendSolRequest>)
    -> Result<ResponseJson<SuccessResponse<SolTransferData>>, (StatusCode, ResponseJson<ErrorResponse>)>
{
    let from = validate_pubkey(&payload.from).map_err(|e| create_error_response(&e))?;
    let to = validate_pubkey(&payload.to).map_err(|e| create_error_response(&e))?;
    if payload.lamports == 0 {
        return Err(create_error_response("Invalid amount"));
    }

    let instruction = system_instruction::transfer(&from, &to, payload.lamports);

    Ok(ResponseJson(SuccessResponse {
        success: true,
        data: SolTransferData {
            program_id: system_program::id().to_string(),
            accounts: vec![from.to_string(), to.to_string()],
            instruction_data: base64::encode(&instruction.data),
        },
    }))
}

async fn send_token(Json(payload): Json<SendTokenRequest>)
    -> Result<ResponseJson<SuccessResponse<TokenTransferData>>, (StatusCode, ResponseJson<ErrorResponse>)>
{
    let destination = validate_pubkey(&payload.destination).map_err(|e| create_error_response(&e))?;
    let mint = validate_pubkey(&payload.mint).map_err(|e| create_error_response(&e))?;
    let owner = validate_pubkey(&payload.owner).map_err(|e| create_error_response(&e))?;
    if payload.amount == 0 {
        return Err(create_error_response("Invalid amount"));
    }

    let source_ata = get_associated_token_address(&owner, &mint);
    let dest_ata = get_associated_token_address(&destination, &mint);

    let instruction = token_instruction::transfer(
        &spl_token::id(),
        &source_ata,
        &dest_ata,
        &owner,
        &[],
        payload.amount,
    ).map_err(|_| create_error_response("Failed to create token transfer instruction"))?;

    let accounts = instruction.accounts.iter().map(|acc| TokenTransferAccount {
        pubkey: acc.pubkey.to_string(),
        is_signer: acc.is_signer,
    }).collect();

    Ok(ResponseJson(SuccessResponse {
        success: true,
        data: TokenTransferData {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: base64::encode(&instruction.data),
        },
    }))
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/keypair", post(generate_keypair))
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token))
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        );

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Server running on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}
