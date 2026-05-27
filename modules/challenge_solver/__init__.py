"""CF/Akamai challenge detection + solver."""
from modules.challenge_solver.detector import (
    ChallengeDetector,
    detect_challenge,
)
from modules.challenge_solver.solver import ChallengeSolver

__all__ = ["ChallengeDetector", "ChallengeSolver", "detect_challenge"]
