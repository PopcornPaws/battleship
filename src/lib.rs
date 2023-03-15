use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Field, SynthesisError},
};
use std::marker::PhantomData;

struct BitInU64Circuit<F: Field> {
    board: Option<u64>,
    index: Option<usize>,
    _marker: PhantomData<F>,
}

impl<F: Field> BitInU64Circuit<F> {
    pub fn new(board: Option<u64>, index: Option<usize>) -> Self {
        Self {
            board,
            index,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> ConstraintSynthesizer<F> for BitInU64Circuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let board_var = cs.new_witness_variable(|| {
            let val = self.board.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(F::from(val))
        })?;
        let index_var = cs.new_input_variable(|| {
            let val = self.index.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(F::from(val as u64))
        })?;

        let bit_val = self.board.map(|x| (x >> self.index.unwrap()));
        let bit_var =
            cs.new_witness_variable(|| bit_val.ok_or(SynthesisError::AssignmentMissing))?;

        let expected_output = match self.board {
            Some(num) => ((num >> self.index.unwrap()) & 1) == 1,
            None => false,
        };
        let expected_output_var =
            cs.new_input_variable(|| Ok(F::from(if expected_output { 1u8 } else { 0u8 })))?;

        cs.constrain((input_var - expected_output_var) * (one_var - res_var));
        Ok(())
    }
}

#[test]
fn test_circuit() {
    let board = Some(35u64);
    let index = Some(4usize);
    let circuit = BitInU64Circuit::<Fields>::new(board, index);

    // Generate parameters for the Groth16 proving system
    let params =
        generate_random_parameters::<Fields, _, _>(circuit.clone(), &mut ark_std::test_rng())
            .unwrap();

    // Create a proof
    let proof = create_random_proof(circuit, &params, &mut ark_std::test_rng()).unwrap();

    // Verify the proof
    let input_var = board.map(|i| vec![i.into()]);
    let bit_idx_var = index.map(|b| vec![b.into()]);
    let expected_output_var = Some(vec![((board.unwrap() >> index.unwrap()) & 1).into()]);
    let success = verify_proof::<Fields, _, _>(
        &params,
        &proof,
        &input_var,
        &bit_idx_var,
        &expected_output_var,
    )
    .unwrap();
    assert!(success);
}
