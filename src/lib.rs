use bellman::{
    gadgets::{
        boolean::{u64_into_boolean_vec_le, AllocatedBit, Boolean},
        multipack,
        sha256::sha256,
    },
    Circuit, ConstraintSystem, SynthesisError,
};
use ff::PrimeField;

/// Our own SHA-256d gadget. Input and output are in little-endian bit order.
fn sha256d<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    data: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
    // Flip endianness of each input byte
    let input: Vec<_> = data
        .chunks(8)
        .map(|c| c.iter().rev())
        .flatten()
        .cloned()
        .collect();

    let hash = sha256(cs.namespace(|| "SHA-256(input)"), &input)?;

    // Flip endianness of each output byte
    Ok(hash
        .chunks(8)
        .map(|c| c.iter().rev())
        .flatten()
        .cloned()
        .collect())
}

pub struct BattleshipCircuit {
    hit: Option<bool>,
    mask: Option<u64>,
    board: Option<u64>,
}

impl<Scalar: PrimeField> Circuit<Scalar> for BattleshipCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Allocate hit flag as public input
        let hit_alloc = AllocatedBit::alloc(cs.namespace(|| "hit alloc"), self.hit)?;
        let mask_bits_alloc = u64_into_boolean_vec_le(cs.namespace(|| "mask alloc"), self.mask)?;
        let board_bits_alloc = u64_into_boolean_vec_le(cs.namespace(|| "board alloc"), self.board)?;

        let mut masked_board_alloc = mask_bits_alloc
            .iter()
            .zip(&board_bits_alloc)
            .enumerate()
            .map(|(i, (m, b))| Boolean::and(cs.namespace(|| format!("and {}", i)), m, b))
            .collect::<Result<Vec<_>, _>>()?;

        assert_eq!(masked_board_alloc.len(), 64);

        let mut half_len = masked_board_alloc.len() / 2;
        let mut j = 0;
        while half_len >= 1 {
            masked_board_alloc = (0..half_len)
                .map(|i| {
                    Boolean::xor(
                        cs.namespace(|| format!("xor {}", j)),
                        &masked_board_alloc[i],
                        &masked_board_alloc[half_len + i],
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            half_len /= 2;
            j += 1;
        }

        assert_eq!(masked_board_alloc.len(), 1);
        let hit_alloc_boolean = Boolean::from(hit_alloc);

        Boolean::enforce_equal(
            cs.namespace(|| "field check"),
            &masked_board_alloc[0],
            &hit_alloc_boolean,
        )?;

        let hash = sha256d(cs.namespace(|| "sha256(board)"), &board_bits_alloc)?;

        let mut public_inputs = Vec::new();
        public_inputs.push(hit_alloc_boolean); // hit alloc should also be made public
        public_inputs.extend(mask_bits_alloc); // mask alloc should also be made public
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

    struct ProofWithInputs {
        proof: groth16::Proof<Bls12>,
        inputs: Vec<Scalar>,
    }

    struct PrivateParams {
        hit: bool,
        mask: u64,
        board: u64,
        hash: [u8; 32],
    }

    impl PrivateParams {
        fn new(hit: bool, index: u8, board: u64) -> Self {
            Self {
                hit,
                mask: 1u64 << index,
                board,
                hash: Sha256::digest(&board.to_le_bytes()).into(),
            }
        }

        fn to_circuit(&self) -> BattleshipCircuit {
            BattleshipCircuit {
                hit: Some(self.hit),
                mask: Some(self.mask),
                board: Some(self.board),
            }
        }

        fn generate_proof_with_inputs(
            &self,
            parameters: &groth16::Parameters<Bls12>,
        ) -> ProofWithInputs {
            let proof = groth16::create_random_proof(self.to_circuit(), parameters, &mut OsRng).unwrap();

            // Pack the hash as inputs for proof verification.
            let mut input_bits = Vec::new();
            input_bits.push(self.hit);
            input_bits.extend(multipack::bytes_to_bits_le(&self.mask.to_le_bytes()));
            input_bits.extend(multipack::bytes_to_bits_le(&self.hash));
            let inputs: Vec<Scalar> = multipack::compute_multipacking(&input_bits);

            ProofWithInputs {
                proof,
                inputs,
            }
        }
    }

    fn setup() -> (
        groth16::PreparedVerifyingKey<Bls12>,
        groth16::Parameters<Bls12>,
    ) {
        // Create parameters for our circuit. In a production deployment these would
        // be generated securely using a multiparty computation.
        println!("GENERATING PARAMS...");
        let c = BattleshipCircuit {
            hit: None,
            mask: None,
            board: None,
        };
        let parameters = groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap();
        // Prepare the verification key (for proof verification).
        println!("PREPARING VERIFYING KEY...");
        (groth16::prepare_verifying_key(&parameters.vk), parameters)
    }

    #[test]
    fn battleship() {
        let (pvk, parameters) = setup();

        let private_params = PrivateParams::new(true, 2, 0b100);
        let proof = private_params.generate_proof_with_inputs(&parameters);
        let result = groth16::verify_proof(&pvk, &proof.proof, &proof.inputs);
        assert!(result.is_ok());

        let private_params = PrivateParams::new(false, 0, 0b100);
        let proof = private_params.generate_proof_with_inputs(&parameters);
        let result = groth16::verify_proof(&pvk, &proof.proof, &proof.inputs);
        assert!(result.is_ok());

        let private_params = PrivateParams::new(true, 1, 0b100);
        let proof = private_params.generate_proof_with_inputs(&parameters);
        let result = groth16::verify_proof(&pvk, &proof.proof, &proof.inputs);
        assert!(!result.is_ok());

        let private_params = PrivateParams::new(true, 7, 0b11111100);
        let proof = private_params.generate_proof_with_inputs(&parameters);
        let result = groth16::verify_proof(&pvk, &proof.proof, &proof.inputs);
        assert!(result.is_ok());
        
        let private_params = PrivateParams::new(false, 63, 0b11111100);
        let proof = private_params.generate_proof_with_inputs(&parameters);
        let result = groth16::verify_proof(&pvk, &proof.proof, &proof.inputs);
        assert!(result.is_ok());
    }
}
