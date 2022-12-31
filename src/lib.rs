use bellman::{
    gadgets::{
        boolean::{u64_into_boolean_vec_le, AllocatedBit, Boolean},
        multipack,
        sha256::sha256,
    },
    Circuit, ConstraintSystem, SynthesisError,
};
use ff::PrimeField;

pub struct BattleshipCircuit {
    //hit: Option<bool>,
    //mask: Option<u64>,
    board: Option<u64>,
}

impl<Scalar: PrimeField> Circuit<Scalar> for BattleshipCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Allocate hit flag as public input
        //let hit_alloc = AllocatedBit::alloc(cs.namespace(|| "hit alloc"), self.hit)?;
        //let mask_bits_alloc = u64_into_boolean_vec_le(cs.namespace(|| "mask alloc"), self.mask)?;
        let board_bits_alloc = u64_into_boolean_vec_le(cs.namespace(|| "board alloc"), self.board)?;

        //let mut masked_board_alloc = mask_bits_alloc
        //    .iter()
        //    .zip(&board_bits_alloc)
        //    .enumerate()
        //    .map(|(i, (m, b))| Boolean::and(cs.namespace(|| format!("and {}", i)), m, b))
        //    .collect::<Result<Vec<_>, _>>()?;

        //assert_eq!(masked_board_alloc.len(), 64);

        //let mut half_len = masked_board_alloc.len() / 2;
        //let mut j = 0;
        //while half_len >= 1 {
        //    masked_board_alloc = (0..half_len)
        //        .map(|i| {
        //            Boolean::xor(
        //                cs.namespace(|| format!("xor {}", j)),
        //                &masked_board_alloc[i],
        //                &masked_board_alloc[half_len + i],
        //            )
        //        })
        //        .collect::<Result<Vec<_>, _>>()?;
        //    half_len /= 2;
        //    j += 1;
        //}

        //assert_eq!(masked_board_alloc.len(), 1);
        //let hit_alloc_boolean = Boolean::from(hit_alloc);

        //Boolean::enforce_equal(
        //    cs.namespace(|| "field check"),
        //    &masked_board_alloc[0],
        //    &hit_alloc_boolean,
        //)?;

        let hash = sha256(cs.namespace(|| "sha256(board)"), &board_bits_alloc)?;

        let mut public_inputs = Vec::new();
        //public_inputs.push(hit_alloc_boolean); // hit alloc should also be made public
        //public_inputs.extend(mask_bits_alloc); // mask alloc should also be made public
        public_inputs.extend(hash); // hash should also be made public

        multipack::pack_into_inputs(cs.namespace(|| "pack input"), &public_inputs)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bellman::groth16;
    use bls::{Bls12, Scalar};
    use rand_core::OsRng;
    use sha2::{Digest, Sha256};

    #[test]
    fn battleship() {
        // Create parameters for our circuit. In a production deployment these would
        // be generated securely using a multiparty computation.
        let params = {
            let c = BattleshipCircuit {
                //hit: None,
                //mask: None,
                board: None,
            };
            groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap()
        };

        // Prepare the verification key (for proof verification).
        let pvk = groth16::prepare_verifying_key(&params.vk);

        // Pick a preimage and compute its hash.
        let hit = true;
        let index = 2;
        let mask: u64 = 1 << index;
        let board: u64 = 4;
        let hash = &Sha256::digest(&board.to_le_bytes());

        // Create an instance of our circuit (with the preimage as a witness).
        let c = BattleshipCircuit {
            //hit: Some(hit),
            //mask: Some(mask),
            board: Some(board),
        };

        // Create a Groth16 proof with our parameters.
        let proof = groth16::create_random_proof(c, &params, &mut OsRng).unwrap();
        // Pack the hash as inputs for proof verification.
        let mut input_bits = Vec::new();
        //input_bits.push(hit);
        //input_bits.extend(multipack::bytes_to_bits_le(&mask.to_le_bytes()));
        input_bits.extend(multipack::bytes_to_bits_le(&hash));
        assert_eq!(input_bits.len(), 32 * 8);
        let inputs: Vec<Scalar> = multipack::compute_multipacking(&input_bits);
        println!("{inputs:?}");

        // Check the proof!
        let result = groth16::verify_proof(&pvk, &proof, &inputs);
        println!("{result:?}");
        assert!(result.is_ok());

        /*
        // Pick a preimage and compute its hash.
        let index = 3;
        let board: u64 = 4;
        let mask: u64 = 1 << index;
        let hit = false;

        //let hash = &Sha256::digest(&board.to_le_bytes());
        // Create an instance of our circuit (with the preimage as a witness).
        let c = BattleshipCircuit {
            hit: Some(hit),
            mask: Some(mask),
            board: Some(board),
        };

        // Create a Groth16 proof with our parameters.
        let proof = groth16::create_random_proof(c, &params, &mut OsRng).unwrap();

        // Pack the hash as inputs for proof verification.
        //let hash_bits = multipack::bytes_to_bits_le(&hash);
        //let mut hash = multipack::compute_multipacking(&hash_bits);
        let mut input_bits = vec![hit];
        input_bits.extend(multipack::bytes_to_bits_le(&mask.to_le_bytes()));
        let inputs: Vec<Scalar> = multipack::compute_multipacking(&input_bits);
        //inputs.append(&mut hash);

        // Check the proof!
        let result = groth16::verify_proof(&pvk, &proof, &inputs);
        assert!(result.is_ok());

        // Pick a preimage and compute its hash.
        let index = 3;
        let board: u64 = 8;
        let mask: u64 = 1 << index;
        let hit = false;

        //let hash = &Sha256::digest(&board.to_le_bytes());
        // Create an instance of our circuit (with the preimage as a witness).
        let c = BattleshipCircuit {
            hit: Some(hit),
            mask: Some(mask),
            board: Some(board),
        };

        // Create a Groth16 proof with our parameters.
        let proof = groth16::create_random_proof(c, &params, &mut OsRng).unwrap();

        // Pack the hash as inputs for proof verification.
        //let hash_bits = multipack::bytes_to_bits_le(&hash);
        //let mut hash = multipack::compute_multipacking(&hash_bits);
        let mut input_bits = vec![hit];
        input_bits.extend(multipack::bytes_to_bits_le(&mask.to_le_bytes()));
        let inputs: Vec<Scalar> = multipack::compute_multipacking(&input_bits);
        //inputs.append(&mut hash);

        // Check the proof!
        let result = groth16::verify_proof(&pvk, &proof, &inputs);
        assert!(result.is_err());

        // Pick a preimage and compute its hash.
        let index = 3;
        let board: u64 = 1;
        let mask: u64 = 1 << index;
        let hit = true;

        //let hash = &Sha256::digest(&board.to_le_bytes());
        // Create an instance of our circuit (with the preimage as a witness).
        let c = BattleshipCircuit {
            hit: Some(hit),
            mask: Some(mask),
            board: Some(board),
        };

        // Create a Groth16 proof with our parameters.
        let proof = groth16::create_random_proof(c, &params, &mut OsRng).unwrap();

        // Pack the hash as inputs for proof verification.
        //let hash_bits = multipack::bytes_to_bits_le(&hash);
        //let mut hash = multipack::compute_multipacking(&hash_bits);
        let mut input_bits = vec![hit];
        input_bits.extend(multipack::bytes_to_bits_le(&mask.to_le_bytes()));
        let inputs: Vec<Scalar> = multipack::compute_multipacking(&input_bits);
        //inputs.append(&mut hash);

        // Check the proof!
        let result = groth16::verify_proof(&pvk, &proof, &inputs);
        assert!(result.is_err());
        */
    }
}
