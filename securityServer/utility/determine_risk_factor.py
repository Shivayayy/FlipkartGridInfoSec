def determine_risk_factor(average_risk_score):
    """
    Determine the risk factor based on the average risk score.

    Args:
        average_risk_score (float): Average risk score calculated from alerts.

    Returns:
        str: Risk factor as a string ('Low', 'Medium', 'High', 'Critical').
    """
    if average_risk_score >= 4:
        return 'Critical'
    elif average_risk_score >= 3:
        return 'High'
    elif average_risk_score >= 2:
        return 'Medium'
    elif average_risk_score >= 1:
        return 'Low'
    else:
        return 'Basic'
