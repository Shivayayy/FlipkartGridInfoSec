def convert_risk_to_score(risk):
    """
    Convert the ZAP risk level to a numerical score.

    Args:
        risk (str): Risk level as a string ('Informational', 'Low', 'Medium', 'High', 'Critical').

    Returns:
        int: Corresponding numerical score for the risk level.
    """
    risk_scores = {
        'Informational': 1,
        'Low': 2,
        'Medium': 3,
        'High': 4,
        'Critical': 5
    }
    return risk_scores.get(risk, 1)  # Default to 1 if risk level is unknown
