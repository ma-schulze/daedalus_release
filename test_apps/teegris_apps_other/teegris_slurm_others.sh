#!/bin/bash -l
#
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=128
#SBATCH --time=24:00:00
#SBATCH --export=NONE
#SBATCH --signal=TERM@120

unset SLURM_EXPORT_ENV


exec ./run_teegris_others.sh