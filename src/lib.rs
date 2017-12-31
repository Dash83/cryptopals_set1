extern crate base64;
extern crate hex;
extern crate crypto;

use base64::encode;
use std::fs::File;
use std::io::Read;
use std::collections::HashMap;
use std::collections::BTreeMap;
use std::io::BufReader;
use std::io::BufRead;
use std::ops::Deref;
use std::cmp;
use crypto::{symmetriccipher, buffer, aes, blockmodes};
use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use std::io::Write;

fn decode_base64(input : &[u8]) -> Vec<u8> {
    base64::decode(input).expect("Could not decode base64 string.")
}

fn encode_base64(input : &[u8]) -> String {
    base64::encode(input)
}

fn hamming_distance(a : &[u8], b : &[u8]) -> u64 {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).fold(0, |acc, (a_i, b_i)| acc + (*a_i ^ *b_i).count_ones() as u64)
}

fn average_hamming_distance(data : &[u8], key_size : usize ) -> f64 {
    let mut sum = 0f64;
    let mut num_blocks = data.len() / key_size;
    let mut block_num = 0; 
    if num_blocks % 2 == 1 {
        num_blocks -= 1;
    }

    while block_num < num_blocks {
        let a_1 =  block_num * key_size;
        let a_2 = (block_num * key_size) + key_size;
        let b_1 = (block_num + 1) * key_size;
        let b_2 = ((block_num + 1) * key_size) + key_size;
        sum += hamming_distance(&data[a_1..a_2], &data[b_1..b_2]) as f64;
        block_num += 2;
    }
    sum / num_blocks as f64
}

fn decode_hex(input : &[u8]) -> Vec<u8> {
    hex::decode(input).expect("Could not decode hex string.")
}

fn encode_hex(input : &[u8]) -> String {
    hex::encode(input)
}

fn transpose_blocks(input : Vec<Vec<u8>> ) -> Vec<Vec<u8>> {
    let num_of_blocks = input[0].len();
    let block_len = input.len();

    let mut output : Vec<Vec<u8>> = Vec::new();
    for i in 0..num_of_blocks {
        //let block = input.clone().into_iter().map(|x| x[i]).collect();
        let mut t_block = Vec::new();
        for input_block in &input {
            //Last block is likely to be smaller. do boundary check.
            if i < input_block.len() {
                t_block.push(input_block[i]);
            }
        }
        output.push(t_block);
    }

    assert_eq!(output.len(), num_of_blocks);
    assert_eq!(output[0].len(), block_len);

    output
}

fn break_into_blocks(input : &[u8], block_size : usize ) -> Vec<Vec<u8>> {
    let mut blocks = Vec::new();
    let mut i : usize = 0;

    while i < input.len() {
        let block = &input[i..cmp::min(i+block_size, input.len())];
        blocks.push(block.to_vec());
        i += block_size;
    }
    println!("{} blocks generated.", blocks.len());
    //println!("First block size: {}.", blocks[0].len());
    //println!("Last block size: {}.", blocks[blocks.len()-1].len());
    blocks
}

fn xor_slice_char(a : &[u8], b : u8) -> Vec<u8> {
    let mut res = Vec::new();
    for x in a.iter() {
        res.push(x ^ b);
    }
    res
}

fn xor_slices(a : &[u8], b : &[u8]) -> Vec<u8> {
    let iter = a.iter().zip(b.iter());
    let mut res = Vec::new();
    for (x, y) in iter {
        res.push(x ^ y);
    }
    res
}

fn build_freq_distrib(input : Vec<u8>) -> HashMap<u8, f64> {
    let mut freq_count = HashMap::new();
    let mut freq_dist = HashMap::new();
    let input_size = input.len();

    for byte in input {
        let counter = freq_count.entry(byte).or_insert(0);
        *counter += 1;
    }

    for (k, v) in freq_count.iter() {
        let val : f64 = *v as f64 / input_size as f64;
        freq_dist.insert(*k, val);
    }
    freq_dist
}

fn get_ascii_frequency_table() -> HashMap<u8, f64> {
    let mut output = HashMap::new();
	output.insert(32, 0.172781714704);
	output.insert(33, 0.000072004029);
	output.insert(34, 0.002458302255);
	output.insert(35, 0.000180010072);
	output.insert(36, 0.000564596297);
	output.insert(37, 0.000160950182);
	output.insert(38, 0.000227024467);
	output.insert(39, 0.002463384892);
	output.insert(40, 0.002192310902);
	output.insert(41, 0.002247796359);
	output.insert(42, 0.000632364794);
	output.insert(43, 0.000216435640);
	output.insert(44, 0.007431662882);
	output.insert(45, 0.013823926431);
	output.insert(46, 0.015222498802);
	output.insert(47, 0.001559099001);
	output.insert(48, 0.005552357730);
	output.insert(49, 0.004623505758);
	output.insert(50, 0.003343528257);
	output.insert(51, 0.001858974603);
	output.insert(52, 0.001357064167);
	output.insert(53, 0.001673458341);
	output.insert(54, 0.001160111971);
	output.insert(55, 0.001036858015);
	output.insert(56, 0.001061000543);
	output.insert(57, 0.001030504719);
	output.insert(58, 0.004382504038);
	output.insert(59, 0.001221527172);
	output.insert(60, 0.001232963106);
	output.insert(61, 0.000228718680);
	output.insert(62, 0.001250328783);
	output.insert(63, 0.001483706547);
	output.insert(64, 0.000073274688);
	output.insert(65, 0.055371521729);
	output.insert(66, 0.012438484205);
	output.insert(67, 0.025198868774);
	output.insert(68, 0.028406012929);
	output.insert(69, 0.089020275064);
	output.insert(70, 0.015239864480);
	output.insert(71, 0.017587195820);
	output.insert(72, 0.029958758634);
	output.insert(73, 0.052570988560);
	output.insert(74, 0.002610357822);
	output.insert(75, 0.007488418999);
	output.insert(76, 0.033852905934);
	output.insert(77, 0.020095900895);
	output.insert(78, 0.052123292922);
	output.insert(79, 0.059931494520);
	output.insert(80, 0.018213630871);
	output.insert(81, 0.001069471605);
	output.insert(82, 0.045399387288);
	output.insert(83, 0.047999579835);
	output.insert(84, 0.067459727511);
	output.insert(85, 0.021954875499);
	output.insert(86, 0.009414738547);
	output.insert(87, 0.015662570485);
	output.insert(88, 0.002308364454);
	output.insert(89, 0.011709549301);
	output.insert(90, 0.000676414318);
	output.insert(91, 0.000086828388);
	output.insert(92, 0.000015671465);
	output.insert(93, 0.000088946153);
	output.insert(94, 0.000003388425);
	output.insert(95, 0.001166888820);
	output.insert(96, 0.000008894615);
	output.insert(97, 0.055371521729);
	output.insert(98, 0.012438484205);
	output.insert(99, 0.025198868774);
	output.insert(100, 0.028406012929);
	output.insert(101, 0.089020275064);
	output.insert(102, 0.015239864480);
	output.insert(103, 0.017587195820);
	output.insert(104, 0.029958758634);
	output.insert(105, 0.052570988560);
	output.insert(106, 0.002610357822);
	output.insert(107, 0.007488418999);
	output.insert(108, 0.033852905934);
	output.insert(109, 0.020095900895);
	output.insert(110, 0.052123292922);
	output.insert(111, 0.059931494520);
	output.insert(112, 0.018213630871);
	output.insert(113, 0.001069471605);
	output.insert(114, 0.045399387288);
	output.insert(115, 0.047999579835);
	output.insert(116, 0.067459727511);
	output.insert(117, 0.021954875499);
	output.insert(118, 0.009414738547);
	output.insert(119, 0.015662570485);
	output.insert(120, 0.002308364454);
	output.insert(121, 0.011709549301);
	output.insert(122, 0.000676414318);
	output.insert(123, 0.000026260293);
	output.insert(124, 0.000006776850);
	output.insert(125, 0.000025836740);
	output.insert(126, 0.000003388425);
    output
}

fn calc_distrib_difference(input : HashMap<u8, f64>, baseline : HashMap<u8, f64>) -> f64 {
    //input.values().zip(baseline.values()).fold(0f64, |acc, (a, b)| acc + (a - b).abs())
    let mut difference = 0f64;
    let default = 0f64;
    for (k,b) in input.iter() {
            let a = baseline.get(k).or(Some(&default)).unwrap();
            difference += (b-a).abs();
    }
    difference
}

fn solve_xor_cypher(input : &[u8] ) -> u8 {
    let chars : Vec<u8> = (0..255).collect();
    let mut best_score = std::f64::MAX;
    let mut candidate_cypher = 0;

    for c in chars {
        let guess = xor_slice_char(input, c);
        let guess_freq_dist = build_freq_distrib(guess.clone());
        let score = calc_distrib_difference(guess_freq_dist, get_ascii_frequency_table());
        //Choose the distribution with minimum distance from the base ascii distribution.
        if score < best_score {
            best_score = score;
            candidate_cypher = c;
        }
    }
    candidate_cypher
}

fn break_repeat_key_xor(input : &[u8], key : &[u8]) -> Vec<u8> {
    let mut unencrypted_data = Vec::new();

    for i in 0..input.len() {
        unencrypted_data.push(input[i] ^ key[i % key.len()]);
    }
    unencrypted_data
}

fn score_guesses( guesses : HashMap<u8, Vec<u8>>, freq_table : HashMap<u8, u32>) -> HashMap<(u32, u8), Vec<u8>> {
    let mut scored_guesses = HashMap::new();

    for (cypher, text) in guesses {
        let mut score :u32 = 0;

        for c in text.clone() {
            //score += *freq_table.get(&c).unwrap_or(&0);
            match freq_table.get(&c) {
                Some(_) => {
                    score += 1;
                },
                None => { /* nothing */ },
            }
        }
        scored_guesses.insert((score, cypher), text);
    }

    scored_guesses
}

fn score_guess(data : Vec<u8>, cypher : u8, freq_table : &HashMap<u8, u32>) -> u32 {
    let mut score = 0;

    for c in data {
        match freq_table.get(&c) {
            Some(_) => {
                score += 1;
            },
            None => { /* nothing */ },
        }
    }
    score
}

fn encode_bytes_hex(input : Vec<u8>) -> String {
    hex::encode(&input)
}

fn encrypt_slice(data : &[u8], key : &[u8]) -> Vec<u8> {
    let key_length = key.len();
    let mut output = Vec::new();
    let mut i = 0;
    for b in data.iter() {
        let key_index = i % key_length;
        output.push(b ^ key[key_index]);
        i+= 1;
    }
    output
}

//From Wikipedia https://en.wikipedia.org/wiki/Letter_frequency checked on 20/12/2017
//letters represented as lowerscore ascii u8.
fn build_letter_frequency_table() -> HashMap<u8, u32> {
    let mut output = HashMap::new();

    output.insert(32, 0); //' '
    output.insert(65, 8167); //A
    output.insert(66, 1492); //B
    output.insert(67, 2782); //C
    output.insert(68, 4253); //D
    output.insert(69, 12702); //E
    output.insert(70, 2228); //F
    output.insert(71, 2015); //G
    output.insert(72, 6094); //H
    output.insert(73, 6966); //I
    output.insert(74, 0153); //J
    output.insert(75, 0772); //K
    output.insert(76, 4025); //L
    output.insert(77, 2406); //M
    output.insert(78, 6749); //N
    output.insert(79, 7507); //O
    output.insert(80, 1929); //P
    output.insert(81, 95); //Q
    output.insert(82, 5987); //R
    output.insert(83, 6327); //S
    output.insert(84, 9056); //T
    output.insert(85, 2758); //U
    output.insert(86, 978); //V
    output.insert(87, 2360); //W
    output.insert(88, 150); //X
    output.insert(89, 1974); //Y
    output.insert(90, 74); //Z

    output.insert(97, 8167); //a
    output.insert(98, 1492); //b
    output.insert(99, 2782); //c
    output.insert(100, 4253); //d
    output.insert(101, 12702); //e
    output.insert(102, 2228); //f
    output.insert(103, 2015); //g
    output.insert(104, 6094); //h
    output.insert(105, 6966); //i
    output.insert(106, 0153); //j
    output.insert(107, 0772); //k
    output.insert(108, 4025); //l
    output.insert(109, 2406); //m
    output.insert(110, 6749); //n
    output.insert(111, 7507); //o
    output.insert(112, 1929); //p
    output.insert(113, 95); //q
    output.insert(114, 5987); //r
    output.insert(115, 6327); //s
    output.insert(116, 9056); //t
    output.insert(117, 2758); //u
    output.insert(118, 978); //v
    output.insert(119, 2360); //w
    output.insert(120, 150); //x
    output.insert(121, 1974); //y
    output.insert(122, 74); //z

    output
}

fn decode_hex_slice<'a>(input : &'a str) -> Vec<u8> {
    hex::decode(input.as_bytes()).expect("Could not decode hex string")
}

fn encrypt_aes128ecb(data : &[u8], key : &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor = aes::ecb_encryptor(aes::KeySize::KeySize128,
                                            key, blockmodes::NoPadding);
    //Buffer to put encrypted bytes
    let mut final_result = Vec::<u8>::new();
    //Buffer reader that will iteratively read from the source data to encrypt
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    //Buffer to write encrypted data into for each iteration.
    let mut buffer = [0; 4096];
    //Buffer writer that will write the encrypted bytes on each iteration.
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            BufferResult::BufferUnderflow => { 
                /* The input buffer is out of data. We are done*/
                break;
            },
            BufferResult::BufferOverflow => {
                /* The intermediate buffer is full. We have (probably) more data to read, so let's loop again. */
            }
        }
    }

    Ok(final_result)
}

fn decrypt_aes128ecb(encrypted_data : &[u8], key : &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::ecb_decryptor( aes::KeySize::KeySize128,
                                            key, blockmodes::NoPadding);
    //Buffer to put encrypted bytes
    let mut final_result = Vec::<u8>::new();
    //Buffer reader that will iteratively read from the source data to encrypt
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    //Buffer to write encrypted data into for each iteration.
    let mut buffer = [0; 4096];
    //Buffer writer that will write the encrypted bytes on each iteration.
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));

        match result {
            BufferResult::BufferUnderflow => { 
                /* The input buffer is out of data. We are done*/
                break;
            },
            BufferResult::BufferOverflow => {
                /* The intermediate buffer is full. We have (probably) more data to read, so let's loop again. */
            }
        }
    }

    Ok(final_result)
}

#[cfg(test)]
mod misc_tests {
    use super::*;

    #[test]
    fn hamming_distance_test1() {
        let a = "this is a test";
        let b = "wokka wokka!!!";
        let expected_distance = 37;        

        assert_eq!( hamming_distance(a.as_bytes(), b.as_bytes()), expected_distance );
    }

    #[test]
    fn test_break_into_blocks() { 
        let input = vec![0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8, 9u8, 
                         10u8, 11u8, 12u8, 13u8, 14u8, 15u8, 16u8, 17u8, 18u8, 19u8, 20u8];
        let expected_value = vec![vec![0, 1, 2, 3], vec![4, 5, 6, 7], vec![8, 9, 10, 11], vec![12, 13, 14, 15], vec![16, 17, 18, 19], vec![20]];
        let key_size = 4;

        let blocks = break_into_blocks(input.as_slice(), key_size);

        assert_eq!(blocks, expected_value);
    }

    #[test]
    fn test_transpose_blocks() { 
        let input = vec![vec![0, 1, 2, 3], vec![4, 5, 6, 7], vec![8, 9, 10, 11], vec![12, 13, 14, 15], vec![16, 17, 18, 19]];
        let expected_value = vec![vec![0, 4, 8, 12, 16], vec![1, 5, 9, 13, 17], vec![2, 6, 10, 14, 18], vec![3, 7, 11, 15, 19]];

        let blocks = transpose_blocks(input);

        assert_eq!(blocks, expected_value);
    }
}

#[cfg(test)]
mod challenges {
    use super::*;

    //********************
    //**** Challenges ****
    //********************

    #[test]
    fn challenge1() {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let hex = decode_hex(input.as_bytes());
        let output = encode_base64(hex.as_slice());

        assert_eq!(expected_output.as_bytes(), output.as_bytes());
    }

    #[test]
    fn challenge2() {
        let input = decode_hex("1c0111001f010100061a024b53535009181c".as_bytes());
        let xor_string = decode_hex("686974207468652062756c6c277320657965".as_bytes());
        let expected_output = decode_hex("746865206b696420646f6e277420706c6179".as_bytes());
        let output = xor_slices(input.as_slice(), xor_string.as_slice());

        assert_eq!(expected_output.as_slice(), output.as_slice());
    }

    #[test]
    fn challenge3() {
        let input = decode_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".as_bytes());
        let expected_output = "Cooking MC's like a pound of bacon";
        let chars : Vec<u8> = (0..255).collect();
        let mut guesses = HashMap::new();

        for c in chars {
            let guess = xor_slice_char(input.as_slice(), c);
            guesses.insert(c, guess);
        }

        let freq = build_letter_frequency_table();

        let results = score_guesses(guesses, freq);
        let mut max_score = 0;
        let mut max_cypher = 0;
        let mut max_bytes = Vec::new();
        for ((score, cypher), bytes) in results {
            if score > max_score {
                max_score = score;
                max_cypher = cypher;
                max_bytes = bytes;
            }
        }

        let text = String::from_utf8(max_bytes).unwrap();
        println!("Best score {} using cypher {} resulting in text {}", max_score, max_cypher, text );

        assert_eq!(expected_output, text);
    }

    #[test]
    fn challenge3_improved() {
        let input = decode_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".as_bytes());
        let expected_output = "Cooking MC's like a pound of bacon";
        let chars : Vec<u8> = (0..255).collect();
        let mut best_score = std::f64::MAX;
        let mut candidate_cypher = 0;
        let mut candidate_solution = Vec::new();

        for c in chars {
            let guess = xor_slice_char(input.as_slice(), c);
            let guess_freq_dist = build_freq_distrib(guess.clone());
            let score = calc_distrib_difference(guess_freq_dist, get_ascii_frequency_table());
            //Choose the distribution with minimum distance from the base ascii distribution.
            if score < best_score {
                best_score = score;
                candidate_cypher = c;
                candidate_solution = guess;
            }
        }

        //let text = String::from_utf8(candidate_solution).unwrap();
        print!("Best score {} using cypher {}.", best_score, candidate_cypher );
        let text = String::from_utf8(candidate_solution).unwrap();
        println!("Resulting in text {}.", text );

        assert_eq!(expected_output, text);
    }

    #[test]
    fn challenge4() {
        let input = "ch4_input.txt";
        let expected_output = "Now that the party is jumping";
        let chars : Vec<u8> = (0..255).collect();
        let mut best_guess_score = 0;
        let mut best_guess_cypher = 0;
        let mut best_guess = Vec::new();
        let freq = build_letter_frequency_table();

        //Apply all cyphers to all lines of the file
        let file = File::open(input).expect("Could not open file.");
        let br = BufReader::new(&file);
        for line in br.lines() {
            let line = line.unwrap_or(String::from(""));
            let decoded_line = decode_hex_slice(&line);

            for c in chars.clone() {
                let guess = xor_slice_char(decoded_line.as_slice(), c);
                let score = score_guess(guess.clone(), c, &freq);

                if score > best_guess_score {
                    best_guess_score = score;
                    best_guess_cypher = c;
                    best_guess = guess;
                }
            }
        }

        //let text = ascii::AsciiStr::from_ascii(max_bytes.as_slice()).unwrap();
        //Remove the last byte of the buffer since the file strings include new line character.
        let guess_len = best_guess.len();
        best_guess.truncate(guess_len - 1);
        let text = String::from_utf8(best_guess).unwrap_or(String::from("INVALID STRING"));
        println!("Best score {} using cypher {} resulting in text \"{}\"", best_guess_score, best_guess_cypher, text );
        assert_eq!(expected_output, text);
    }

    #[test]
    fn challenge5() {
        let input = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let expected_output = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        let encryption_key = "ICE";

        let encrypted_bytes = encrypt_slice(input.as_bytes(), encryption_key.as_bytes());

        let output_text = encode_bytes_hex(encrypted_bytes);
        assert_eq!(&output_text, expected_output);
    }

    #[test]
    fn challenge6() {
        let input_file = "ch6_input.txt";
        let output_file = "ch6_expected_output.txt";
        let MAX_KEY_SIZE = 40;
        let MIN_KEY_SIZE = 2;
        let mut f = File::open(input_file).expect("Could not open file.");
        let mut encoded_data = String::new();
        let mut expected_output = String::new();

        //The file data is base64 encoded but segmented by lines. Read line by line
        //and append to data buffer.
        let br = BufReader::new(f);
        for line in br.lines() {
            let line = line.unwrap();
            encoded_data.push_str(&line);
        }

        //Open the file with the expected output. This was not provided but since I already cracked
        //the challenge, its a good way to to make sure the code keeps working.
        f = File::open(output_file).expect("Could not open file.");;
        f.read_to_string(&mut expected_output);

        //let _size = f.read_to_end(&mut encoded_data).expect("Could not read file data.");
        //The data is base64 enconded, so, decode it.
        let data = decode_base64(encoded_data.as_bytes());
        println!("Decoded {} bytes of data.", data.len());

        let mut results = BTreeMap::new();
        let mut best_key_size = MAX_KEY_SIZE;
        let mut smallest_norm_hamm_dist = std::f64::MAX;
        for key_size in MIN_KEY_SIZE..MAX_KEY_SIZE+1 {
            let ham_dist = average_hamming_distance(data.as_slice(), key_size);
            let ham_dist_norm : f64 = ham_dist as f64 / key_size as f64;
            results.insert(key_size, ham_dist_norm);

            //Keep track of the key size that matches the smallest normalized hamming distance
            if ham_dist_norm < smallest_norm_hamm_dist {
                best_key_size = key_size;
                smallest_norm_hamm_dist = ham_dist_norm;
            }
        }

        //Now transpose the data in key_size-sized blocks
        println!("Generating blocks with key size {}", best_key_size);
        
        let data_blocks = break_into_blocks(data.as_slice(), best_key_size);
        let data_blocks = transpose_blocks(data_blocks);

        //We now solve each block as individual xor cypher and obtain 1 byte of the key per block
        let mut key = Vec::new();
        for block in data_blocks {
             let key_byte = solve_xor_cypher(block.as_slice());
             key.push(key_byte);
        }

        println!("Key is {:?}", key);

        let output = break_repeat_key_xor(data.as_slice(), key.as_slice());
        
        let unencrypted_text = String::from_utf8(output).unwrap();

        //println!("Unencrypted text: {}", unencrypted_text);

        assert_eq!(unencrypted_text, expected_output);
    }

    #[test]
    fn challenge7() {
        let input_file = "ch7_input.txt";
        let output_file = "ch7_expected_output.txt";
        let key = "YELLOW SUBMARINE";
        let mut f = File::open(input_file).expect("Could not read input file.");
        let mut encoded_data = String::new();
        let mut expected_output = String::new();
        
        //Read and decode the input file
        //The file data is base64 encoded but segmented by lines. Read line by line
        //and append to data buffer.
        let br = BufReader::new(f);
        for line in br.lines() {
            let line = line.unwrap();
            encoded_data.push_str(&line);
        }

        let decoded_data = decode_base64(encoded_data.as_bytes()); 

        //Read the expected output file
        f = File::open(output_file).expect("Could not open file.");;
        f.read_to_string(&mut expected_output);

        //Descrypt the data
        let mut decrypted_data = decrypt_aes128ecb(decoded_data.as_slice(), key.as_bytes()).expect("Could not decrypt data.");
        //f = File::create("output8.txt").unwrap();
        //f.write_all(&mut decrypted_data);
        let decrypted_text = String::from_utf8(decrypted_data).unwrap();

        //println!("{:?}", decrypted_text);

        assert_eq!(expected_output, decrypted_text);;
        //panic!("aaa");
    }
}
