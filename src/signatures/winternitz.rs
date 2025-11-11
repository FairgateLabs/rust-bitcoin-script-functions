use bitcoin::secp256k1::SecretKey;
use bitcoin_script_stack::stack::{StackTracker, StackVariable};
pub const DIGITS_PER_BIT: u8 = 4;
pub const BASE: u8 = 1 << DIGITS_PER_BIT;
pub const MAX: u8 = BASE - 1;

pub type WinternitzSignature = Vec<u8>;

//assumes that the altstack contains the digits of the message
fn digits_checksum(
    stack: &mut StackTracker,
    message_size: u32,
    max: u8,
    keep_message: bool,
) -> StackVariable {
    stack.number(max as u32 * message_size);
    let mut ret = StackVariable::null();

    for _ in 0..message_size {
        stack.from_altstack();
        if keep_message {
            stack.op_tuck();
        }
        ret = stack.op_sub();
    }

    ret
}

//assumes that the altstack contains the digits of the checksum with the high part being the first to be obtained
fn reconstruct_checksum(stack: &mut StackTracker, checksum_size: u32, bits: u8) -> StackVariable {
    stack.from_altstack();

    let mut ret = StackVariable::null();
    for _ in 0..checksum_size - 1 {
        for _ in 0..bits {
            stack.op_dup();
            stack.op_add();
        }
        stack.from_altstack();
        ret = stack.op_add();
    }
    ret
}

fn verify_digits(stack: &mut StackTracker, public_keys: &Vec<String>, max: u8) {
    const PUBLIC_KEY_SIZE: u32 = 20;

    for digit in 0..public_keys.len() {
        // This is a sanitization of the hint to ensure the hint do not exceed the max times to hash the secret key.
        stack.number(max as u32);
        stack.op_min();

        // Save two copies of the hint
        stack.op_dup();
        stack.to_altstack();
        stack.to_altstack();

        // Check if the public key is 20 bytes
        stack.op_size();
        stack.number(PUBLIC_KEY_SIZE);
        stack.op_equalverify();

        //creates all the hashes from the provided secret key on the stack
        for _ in 0..max {
            stack.op_dup();
            stack.op_hash160();
        }

        stack.from_altstack();
        stack.op_pick();

        stack.hexstr(&public_keys[digit]);
        stack.op_equalverify();

        for _ in 0..(max + 1) / 2 {
            stack.op_2drop();
        }
    }
}

pub fn winternitz_checksig(
    stack: &mut StackTracker,
    public_keys: &Vec<String>,
    message_size: u32,
    max: u8,
    bits_per_digit: u8,
    keep_message: bool,
) {
    verify_digits(stack, &public_keys, max);
    let checksum = digits_checksum(stack, message_size, max, keep_message);
    let checksum_size = public_keys.len() as u32 - message_size;
    let reconstructed = reconstruct_checksum(stack, checksum_size, bits_per_digit);
    stack.equals(checksum, true, reconstructed, true);

    if keep_message {
        for _ in 0..message_size {
            stack.to_altstack();
        }
    }
}

pub fn get_winternitz_checksig_script(
    public_keys: &Vec<String>,
    message_size: u32,
    max: u8,
    bits_per_digit: u8,
    keep_message: bool,
) -> bitcoin::ScriptBuf {
    let mut stack = StackTracker::new();

    // Define the public keys and hints in the stack (needed for the stack tracker to work)
    for i in 0..public_keys.len() {
        stack.define(1, format!("public_key_{}", i).as_str());
        stack.define(1, format!("hint_{}", i).as_str());
    }

    winternitz_checksig(
        &mut stack,
        public_keys,
        message_size,
        max,
        bits_per_digit,
        keep_message,
    );

    // Return the script from the stack tracker, defined variables are not included in the script.
    stack.get_script()
}

#[cfg(test)]
mod tests {

    use super::*;
    use bitcoin::hashes::{ripemd160, sha256, Hash};

    fn hash160(data: &str) -> String {
        let data = hex::decode(data).unwrap();
        let sha256 = sha256::Hash::hash(&data);
        let rip = ripemd160::Hash::hash(sha256.as_byte_array());
        hex::encode(rip)
    }

    fn public_key(secret: &str, max: u8) -> String {
        sign_digit(secret, max)
    }

    fn sign_digit(secret: &str, digit: u8) -> String {
        let mut ret = secret.to_string();
        for _ in 0..digit {
            ret = hash160(&ret);
        }
        ret
    }

    fn calculate_checksum(msg: &Vec<u8>, max_value_digit: u8) -> u32 {
        let sum = msg.iter().sum::<u8>() as u32;
        let max_value_all = max_value_digit as u32 * msg.len() as u32;
        assert!(sum <= max_value_all as u32);
        max_value_all as u32 - sum
    }

    fn to_base_padded(mut num: u32, base: u8, max_num: u32) -> Vec<u8> {
        assert!(base > 1, "Base must be greater than 1");

        let mut result = Vec::new();

        if num == 0 {
            result.push(0);
        }

        while num > 0 {
            result.push((num % base as u32) as u8);
            num /= base as u32;
        }

        // Calculate the fixed length based on max_num
        let mut max_digits = 0;
        let mut temp = max_num;
        while temp > 0 {
            max_digits += 1;
            temp /= base as u32;
        }

        // Ensure the vector has the required length by padding with 0s
        while result.len() < max_digits {
            result.push(0);
        }

        result.reverse(); // Reverse to maintain the correct order
        result
    }

    #[test]
    fn test_verify_digits() {
        let mut stack = StackTracker::new();

        // Max hashes until public key
        // priv_0 = secret
        // priv_1 = H(secret)
        // priv_2 = H(priv_1)
        // public_key = H(priv_2)
        let times_to_pubkey = 3;
        let hint = 0; // This could be 0, 1, or 2.

        // Secret key should be 20 bytes otherwise the script will fail (in case hint 0 = priv_0 = secret)
        let secret = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let public_key = public_key(secret, times_to_pubkey);
        let signed = sign_digit(secret, hint);

        stack.hexstr(&signed);
        stack.number(hint as u32);

        verify_digits(&mut stack, &vec![public_key], times_to_pubkey);

        stack.op_true();
        assert!(stack.run().success);
    }

    #[test]
    fn test_reconstruct_checksum() {
        let mut stack = StackTracker::new();
        let checksum = vec![1, 2, 3];
        for d in checksum.iter() {
            stack.number(*d as u32);
        }
        for _ in 0..checksum.len() {
            stack.to_altstack();
        }

        let result = reconstruct_checksum(&mut stack, checksum.len() as u32, 2);
        let expected = stack.number(1 * 16 + 2 * 4 + 3);
        stack.equals(result, true, expected, true);
        stack.op_true();
        assert!(stack.run().success);
    }

    #[test]
    fn test_digits_checksum() {
        let mut stack = StackTracker::new();

        let digits = vec![2, 3, 3];

        for d in digits.iter() {
            stack.number(*d as u32);
        }
        for _ in 0..digits.len() {
            stack.to_altstack();
        }

        let max = 3;
        let result = digits_checksum(&mut stack, digits.len() as u32, max, false);
        let sum = digits.iter().sum::<u32>();
        let expected = stack.number((max as u32 * digits.len() as u32) - sum);
        stack.equals(result, true, expected, true);
        stack.op_true();
        assert!(stack.run().success);
    }

    #[test]
    fn test_winternitz_keep_message() {
        let mut stack = StackTracker::new();

        let message_size = 2;
        let max = MAX;
        let base = BASE;
        let bits_per_digit = 4;

        let secrets = vec!["00", "11", "22", "33"]
            .iter()
            .map(|s| hash160(s))
            .collect::<Vec<String>>();

        let public_keys = secrets.iter().rev().map(|s| public_key(s, max)).collect();

        let msg = vec![15, 15];

        // witness generation
        let checksum = calculate_checksum(&msg, max);
        let checksum_digits = to_base_padded(checksum, base, max as u32 * msg.len() as u32);
        let msg_and_chk: Vec<u8> = msg.iter().chain(checksum_digits.iter()).cloned().collect();

        for i in 0..msg_and_chk.len() {
            stack.hexstr(&sign_digit(&secrets[i], msg_and_chk[i] as u8));
            stack.number(msg_and_chk[i] as u32);
        }

        // verification script

        winternitz_checksig(
            &mut stack,
            &public_keys,
            message_size,
            max,
            bits_per_digit,
            true,
        );

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_winternitz_do_not_keep_message() {
        let mut stack = StackTracker::new();

        let message_size = 2;
        let max = MAX;
        let base = BASE;
        let bits_per_digit = 4;

        let secrets = vec!["00", "11", "22", "33"]
            .iter()
            .map(|s| hash160(s))
            .collect::<Vec<String>>();

        let public_keys = secrets.iter().rev().map(|s| public_key(s, max)).collect();

        let msg = vec![15, 15];

        // witness generation
        let checksum = calculate_checksum(&msg, max);
        let checksum_digits = to_base_padded(checksum, base, max as u32 * msg.len() as u32);
        let msg_and_chk: Vec<u8> = msg.iter().chain(checksum_digits.iter()).cloned().collect();

        for i in 0..msg_and_chk.len() {
            stack.hexstr(&sign_digit(&secrets[i], msg_and_chk[i] as u8));
            stack.number(msg_and_chk[i] as u32);
        }

        // verification script

        winternitz_checksig(
            &mut stack,
            &public_keys,
            message_size,
            max,
            bits_per_digit,
            false,
        );

        stack.op_true();

        assert!(stack.run().success);
    }
}
