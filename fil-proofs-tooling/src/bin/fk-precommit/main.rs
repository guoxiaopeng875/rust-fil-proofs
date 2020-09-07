use std::io::{Seek, SeekFrom, Write};
use std::sync::Once;

use anyhow::Result;
use ff::Field;
use paired::bls12_381::Fr;
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use tempfile::NamedTempFile;

use filecoin_proofs::*;

static INIT_LOGGER: Once = Once::new();

fn init_logger() {
    INIT_LOGGER.call_once(|| {
        fil_logger::init();
    });
}

const TEST_SEED: [u8; 16] = [
    0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc, 0xe5,
];

fn main() {
    init_logger();
    match seal_lifecycle::<SectorShape32GiB>(SECTOR_SIZE_32_GIB) {
        Err(e) => println!("error seal_lifecycle: {:?}", e),
        _ => {}
    }
}

fn seal_lifecycle<Tree: 'static + MerkleTreeTrait>(sector_size: u64) -> Result<()> {
    let rng = &mut XorShiftRng::from_seed(TEST_SEED);
    let prover_fr: DefaultTreeDomain = Fr::random(rng).into();
    let mut prover_id = [0u8; 32];
    prover_id.copy_from_slice(AsRef::<[u8]>::as_ref(&prover_fr));

    create_seal::<_, Tree>(rng, sector_size, prover_id)?;
    Ok(())
}

fn create_seal<R: Rng, Tree: 'static + MerkleTreeTrait>(
    rng: &mut R,
    sector_size: u64,
    prover_id: ProverId,
) -> Result<()> {
    init_logger();

    let number_of_bytes_in_piece = UnpaddedBytesAmount::from(PaddedBytesAmount(sector_size));

    let piece_bytes: Vec<u8> = (0..number_of_bytes_in_piece.0)
        .map(|_| rand::random::<u8>())
        .collect();

    let mut piece_file = NamedTempFile::new()?;
    piece_file.write_all(&piece_bytes)?;
    piece_file.as_file_mut().sync_all()?;
    piece_file.as_file_mut().seek(SeekFrom::Start(0))?;

    let piece_info = generate_piece_commitment(piece_file.as_file_mut(), number_of_bytes_in_piece)?;
    piece_file.as_file_mut().seek(SeekFrom::Start(0))?;

    let mut staged_sector_file = NamedTempFile::new()?;
    add_piece(
        &mut piece_file,
        &mut staged_sector_file,
        number_of_bytes_in_piece,
        &[],
    )?;

    let piece_infos = vec![piece_info];
    let arbitrary_porep_id = [28; 32];
    let sealed_sector_file = NamedTempFile::new()?;
    let config = PoRepConfig {
        sector_size: SectorSize(sector_size),
        partitions: PoRepProofPartitions(
            *POREP_PARTITIONS
                .read()
                .expect("POREM_PARTITIONS poisoned")
                .get(&sector_size)
                .expect("unknown sector size"),
        ),
        porep_id: arbitrary_porep_id,
    };

    let cache_dir = tempfile::tempdir().expect("failed to create temp dir");

    let ticket = rng.gen();
    let sector_id = rng.gen::<u64>().into();

    seal_pre_commit_phase1::<_, _, _, Tree>(
        config,
        cache_dir.path(),
        staged_sector_file.path(),
        sealed_sector_file.path(),
        prover_id,
        sector_id,
        ticket,
        &piece_infos,
    )?;
    Ok(())
}