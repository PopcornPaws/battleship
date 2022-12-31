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
    index: Option<u8>,
    hit: Option<bool>,
    board: Option<u64>,
}

impl<Scalar: PrimeField> Circuit<Scalar> for BattleshipCircuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Allocate index as public input
        let _index_alloc = cs.alloc_input(
            || "index",
            || {
                self.index
                    .map(|x| Scalar::from(u64::from(x)))
                    .ok_or(SynthesisError::AssignmentMissing)
            },
        )?;
        // Allocate hit flag as public input
        let hit_alloc = AllocatedBit::alloc(cs.namespace(|| "hit alloc"), self.hit)?;
        // Allocate the board fields as bits
        let board_bits_alloc = u64_into_boolean_vec_le(cs.namespace(|| "board alloc"), self.board)?;

        // enforce boolean hit/miss check in constraint
        let hit_alloc_boolean = Boolean::from(hit_alloc);

        if let Some(i) = self.index {
            Boolean::enforce_equal(
                cs.namespace(|| "field check"),
                board_bits_alloc
                    .get(usize::from(i))
                    .ok_or(SynthesisError::AssignmentMissing)?,
                &hit_alloc_boolean,
            )?;
        }

        //let mut public_inputs = sha256(cs.namespace(|| "sha256(board)"), &board_bits_alloc)?;
        let mut public_inputs = Vec::new();
        public_inputs.push(hit_alloc_boolean); // hit alloc should also be made public

        // Expose the vector of 32 + 1 boolean variables as compact public inputs.
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
                index: None,
                hit: None,
                board: None,
            };
            groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap()
        };

        // Prepare the verification key (for proof verification).
        let pvk = groth16::prepare_verifying_key(&params.vk);

        // Pick a preimage and compute its hash.
        let board = 4u64;
        let index = 2u8;
        let hit = true;

        //let hash = &Sha256::digest(&board.to_le_bytes());
        // Create an instance of our circuit (with the preimage as a witness).
        let c = BattleshipCircuit {
            index: Some(index),
            hit: Some(hit),
            board: Some(board),
        };

        // Create a Groth16 proof with our parameters.
        let proof = groth16::create_random_proof(c, &params, &mut OsRng).unwrap();

        // Pack the hash as inputs for proof verification.
        //let hash_bits = multipack::bytes_to_bits_le(&hash);
        //let mut hash = multipack::compute_multipacking(&hash_bits);
        
        let mut inputs = vec![Scalar::from(u64::from(index))];
        //inputs.append(&mut hash);
        inputs.push(Scalar::from(u64::from(hit)));

        // Check the proof!
        assert!(groth16::verify_proof(&pvk, &proof, &inputs).is_ok());
    }
}
