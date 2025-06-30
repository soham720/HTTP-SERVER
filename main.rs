use axum::{
    extract::Json,
    http::StatusCode,
    response::Json as ResponseJson,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use solana_program::{pubkey::Pubkey, system_instruction, system_program};
use solana_sdk::signature::{Keypair, Signer};
use spl_token::instruction as token_instruction;
use spl_associated_token_account::get_associated_token_address;
use std::str::FromStr;
use ed25519_dalek::{Keypair as EdKeypair, PublicKey, Signature as EdSignature, Signer as DalekSigner, Verifier};
use rand::rngs::OsRng;
use rand_core::CryptoRng;
use base64::{engine::general_purpose::STANDARD, Engine};
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
    isSigner: bool,
    isWritable: bool,
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
    isSigner: bool,
}

#[derive(Serialize)]
struct TokenTransferData {
    program_id: String,
    accounts: Vec<TokenTransferAccount>,
    instruction_data: String,
}

fn create_error_response(msg: &str) -> (StatusCode, ResponseJson<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        ResponseJson(ErrorResponse {
            success: false,
            error: msg.to_string(),
        }),
    )
}

fn validate_pubkey(s: &str) -> Result<Pubkey, String> {
    Pubkey::from_str(s).map_err(|_| "Invalid public key format".to_string())
}

fn validate_secret_key(s: &str) -> Result<[u8; 64], String> {
    let bytes = bs58::decode(s).into_vec().map_err(|_| "Invalid secret key format")?;
    if bytes.len() != 64 {
        return Err("Invalid secret key length".to_string());
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

async fn generate_keypair() -> ResponseJson<SuccessResponse<KeypairData>> {
    let mut rng = OsRng;
    let kp = Keypair::generate(&mut rng);
    let pubkey = kp.pubkey().to_string();
    let secret = bs58::encode(kp.to_bytes()).into_string();
    ResponseJson(SuccessResponse {
        success: true,
        data: KeypairData { pubkey, secret },
    })
}

async fn create_token(Json(p): Json<CreateTokenRequest>) -> Result<ResponseJson<SuccessResponse<InstructionData>>, (StatusCode, ResponseJson<ErrorResponse>)> {
    let mint_auth = validate_pubkey(&p.mint_authority).map_err(|e| create_error_response(&e))?;
    let mint = validate_pubkey(&p.mint).map_err(|e| create_error_response(&e))?;
    let inst = token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_auth,
        Some(&mint_auth),
        p.decimals,
    ).map_err(|_| create_error_response("Failed to create mint instruction"))?;
    let accounts = inst.accounts.into_iter().map(|a| AccountMetaData {
        pubkey: a.pubkey.to_string(),
        isSigner: a.is_signer,
        isWritable: a.is_writable,
    }).collect();
    Ok(ResponseJson(SuccessResponse {
        success: true,
        data: InstructionData {
            program_id: inst.program_id.to_string(),
            accounts,
            instruction_data: STANDARD.encode(&inst.data),
        },
    }))
}

async fn mint_token(Json(p): Json<MintTokenRequest>) -> Result<ResponseJson<SuccessResponse<InstructionData>>, (StatusCode, ResponseJson<ErrorResponse>)> {
    let mint = validate_pubkey(&p.mint).map_err(|e| create_error_response(&e))?;
    let dest = validate_pubkey(&p.destination).map_err(|e| create_error_response(&e))?;
    let auth = validate_pubkey(&p.authority).map_err(|e| create_error_response(&e))?;
    let inst = token_instruction::mint_to(&spl_token::id(), &mint, &dest, &auth, &[], p.amount)
        .map_err(|_| create_error_response("Failed to create mint instruction"))?;
    let accounts = inst.accounts.into_iter().map(|a| AccountMetaData {
        pubkey: a.pubkey.to_string(),
        isSigner: a.is_signer,
        isWritable: a.is_writable,
    }).collect();
    Ok(ResponseJson(SuccessResponse {
        success: true,
        data: InstructionData {
            program_id: inst.program_id.to_string(),
            accounts,
            instruction_data: STANDARD.encode(&inst.data),
        },
    }))
}

async fn sign_message(Json(p): Json<SignMessageRequest>) -> Result<ResponseJson<SuccessResponse<SignatureData>>, (StatusCode, ResponseJson<ErrorResponse>)> {
    if p.message.is_empty() || p.secret.is_empty() {
        return Err(create_error_response("Missing required fields"));
    }
    let sk = validate_secret_key(&p.secret).map_err(|e| create_error_response(&e))?;
    let edkp = EdKeypair::from_bytes(&sk).map_err(|_| create_error_response("Invalid secret key"))?;
    let sig = edkp.sign(p.message.as_bytes());
    Ok(ResponseJson(SuccessResponse {
        success: true,
        data: SignatureData {
            signature: STANDARD.encode(sig.to_bytes()),
            public_key: bs58::encode(edkp.public.to_bytes()).into_string(),
            message: p.message,
        },
    }))
}

async fn verify_message(Json(p): Json<VerifyMessageRequest>) -> Result<ResponseJson<SuccessResponse<VerifyData>>, (StatusCode, ResponseJson<ErrorResponse>)> {
    if p.message.is_empty() || p.signature.is_empty() || p.pubkey.is_empty() {
        return Err(create_error_response("Missing required fields"));
    }
    let sig_bytes = STANDARD.decode(&p.signature).map_err(|_| create_error_response("Invalid signature format"))?;
    let pk_bytes = bs58::decode(&p.pubkey).into_vec().map_err(|_| create_error_response("Invalid public key format"))?;
    if pk_bytes.len() != 32 {
        return Err(create_error_response("Invalid public key length"));
    }
    let public_key = PublicKey::from_bytes(&pk_bytes).map_err(|_| create_error_response("Invalid public key"))?;
    let ed_sig = EdSignature::from_bytes(&sig_bytes).map_err(|_| create_error_response("Invalid signature"))?;
    let valid = public_key.verify(p.message.as_bytes(), &ed_sig).is_ok();
    Ok(ResponseJson(SuccessResponse {
        success: true,
        data: VerifyData {
            valid,
            message: p.message,
            pubkey: p.pubkey,
        },
    }))
}

async fn send_sol(Json(p): Json<SendSolRequest>) -> Result<ResponseJson<SuccessResponse<SolTransferData>>, (StatusCode, ResponseJson<ErrorResponse>)> {
    let from = validate_pubkey(&p.from).map_err(|e| create_error_response(&e))?;
    let to = validate_pubkey(&p.to).map_err(|e| create_error_response(&e))?;
    if p.lamports == 0 {
        return Err(create_error_response("Invalid amount"));
    }
    let inst = system_instruction::transfer(&from, &to, p.lamports);
    Ok(ResponseJson(SuccessResponse {
        success: true,
        data: SolTransferData {
            program_id: system_program::id().to_string(),
            accounts: vec![from.to_string(), to.to_string()],
            instruction_data: STANDARD.encode(&inst.data),
        },
    }))
}

async fn send_token(Json(p): Json<SendTokenRequest>) -> Result<ResponseJson<SuccessResponse<TokenTransferData>>, (StatusCode, ResponseJson<ErrorResponse>)> {
    let dst = validate_pubkey(&p.destination).map_err(|e| create_error_response(&e))?;
    let mint = validate_pubkey(&p.mint).map_err(|e| create_error_response(&e))?;
    let owner = validate_pubkey(&p.owner).map_err(|e| create_error_response(&e))?;
    if p.amount == 0 {
        return Err(create_error_response("Invalid amount"));
    }
    let source_ata = get_associated_token_address(&owner, &mint);
    let dest_ata = get_associated_token_address(&dst, &mint);
    let inst = token_instruction::transfer(&spl_token::id(), &source_ata, &dest_ata, &owner, &[], p.amount)
        .map_err(|_| create_error_response("Failed to create token transfer instruction"))?;
    let accounts = inst.accounts.into_iter().map(|a| TokenTransferAccount {
        pubkey: a.pubkey.to_string(),
        isSigner: a.is_signer,
    }).collect();
    Ok(ResponseJson(SuccessResponse {
        success: true,
        data: TokenTransferData {
            program_id: inst.program_id.to_string(),
            accounts,
            instruction_data: STANDARD.encode(&inst.data),
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
        .layer(tower_http::cors::CorsLayer::new().allow_origin(tower_http::cors::Any).allow_methods(tower_http::cors::Any).allow_headers(tower_http::cors::Any));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Server http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}
