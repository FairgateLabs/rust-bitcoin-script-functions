use bitcoin_script_stack::stack::{StackTracker, StackVariable};

pub const BASE: u8 = 4;

pub type WinternitzSignature = Vec<u8>;

//pub fn pub_key_gen(sec_key: &[u8]) {}

//pub fn witernitz_verification(message_size: u32, checksum_size: u32, base: u32) {}

//create mod test
//nbits = 2
//W = 3

//assumes that the altstack contains the digits of the message
pub fn digits_checksum(
    stack: &mut StackTracker,
    message_size: u32,
    base: u8,
    keep_message: bool,
) -> StackVariable {
    stack.number(base as u32 * message_size);
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
pub fn reconstruct_checksum(
    stack: &mut StackTracker,
    checksum_size: u32,
    bits: u8,
) -> StackVariable {
    stack.debug();
    stack.from_altstack();
    stack.debug();

    let mut ret = StackVariable::null();
    for _ in 0..checksum_size - 1 {
        for _ in 0..bits {
            stack.op_dup();
            stack.op_add();
        }
        stack.from_altstack();
        ret = stack.op_add();
        stack.debug();
    }
    ret
}

pub fn verify_digits(stack: &mut StackTracker, public_keys: &Vec<String>, base: u8) {
    for digit in 0..public_keys.len() {
        //sanitize hint
        stack.number(base as u32);
        stack.op_min();

        //save two copies of the hint
        stack.op_dup();
        stack.to_altstack();
        stack.to_altstack();

        //creates all the hashes from the provided secret key on the stack
        for _ in 0..base {
            stack.op_dup();
            stack.op_hash160();
        }

        stack.number(base as u32);
        stack.from_altstack();
        stack.op_sub();

        stack.op_pick();

        stack.hexstr(&public_keys[digit]);

        stack.debug();

        stack.op_equalverify();

        for _ in 0..(base + 1) / 2 {
            stack.op_2drop();
        }
    }
}

pub fn verify_winternitz(
    stack: &mut StackTracker,
    public_keys: &Vec<String>,
    message_size: u32,
    base: u8,
    bits_per_digit: u8,
    keep_message: bool,
) {
    verify_digits(stack, &public_keys, base);
    let checksum = digits_checksum(stack, message_size, base, keep_message);
    let checksum_size = public_keys.len() as u32 - message_size;
    let reconstructed = reconstruct_checksum(stack, checksum_size, bits_per_digit);
    stack.equals(checksum, true, reconstructed, true);
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

    fn public_key(secret: &str, base: u8) -> String {
        sign_digit(secret, base, 0)
    }

    fn sign_digit(secret: &str, base: u8, digit: u8) -> String {
        let mut ret = secret.to_string();
        for _ in 0..(base - digit) {
            ret = hash160(&ret);
        }
        ret
    }

    fn calculate_checksum(msg: &Vec<u8>, base: u8) -> u32 {
        let sum = msg.iter().sum::<u8>() as u32;
        let max = base as u32 * msg.len() as u32;
        assert!(sum < max as u32);
        max as u32 - sum
    }

    fn to_base_padded(mut num: u32, mut base: u8, max_num: u32) -> Vec<u8> {
        base += 1;
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

        let base = 3;

        let digit = 0;
        let secret = "010234242342349203";
        let public_key = public_key(secret, base);
        let signed = sign_digit(secret, base, digit);

        stack.hexstr(&signed);
        stack.number(digit as u32);

        verify_digits(&mut stack, &vec![public_key], base);

        stack.debug();
        //<0x00>
        //<0x9f7fd096d37ed2c0e3f7f0cfc924beef4ffceb68>
        //<0x57622f345f73e1acadf0de4ce367dff391afa3a7>
        //<0x9724e32791f98971fd669d03c6bfdaa3aea491c9>
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
        stack.debug();
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

        let base = 3;
        let result = digits_checksum(&mut stack, digits.len() as u32, base, false);
        let sum = digits.iter().sum::<u32>();
        let expected = stack.number((base as u32 * digits.len() as u32) - sum);
        stack.equals(result, true, expected, true);
        stack.op_true();
        assert!(stack.run().success);
    }

    #[test]
    fn test_winternitz() {
        let mut stack = StackTracker::new();

        let message_size = 2;
        let base = 3;
        let bits_per_digit = 2;

        let secret_0 = "001122";
        let secret_1 = "223344";
        let checksum_0 = "336677";
        let checksum_1 = "446677";

        let secrets = vec![secret_0, secret_1, checksum_0, checksum_1];
        let msg = vec![1, 1];

        // witness generation
        let checksum = calculate_checksum(&msg, base);
        let checksum_digits = to_base_padded(checksum, base, base as u32 * msg.len() as u32);
        let mut msg_and_chk: Vec<u8> = msg.iter().chain(checksum_digits.iter()).cloned().collect();
        msg_and_chk.reverse();

        for i in 0..msg_and_chk.len() {
            stack.hexstr(&sign_digit(&secrets[i], base, msg_and_chk[i] as u8));
            stack.number(msg_and_chk[i] as u32);
            stack.to_altstack();
            stack.to_altstack();
        }
        for _ in 0..msg_and_chk.len() {
            stack.from_altstack();
            stack.from_altstack();
        }

        // verification script
        let public_keys = vec![
            public_key(secret_0, base),
            public_key(secret_1, base),
            public_key(checksum_0, base),
            public_key(checksum_1, base),
        ];

        verify_winternitz(
            &mut stack,
            &public_keys,
            message_size,
            base,
            bits_per_digit,
            false,
        );

        stack.op_true();
        assert!(stack.run().success);
    }
}
