import streamlit as st
import plotly.express as px

st.title("🛡️ Security Auditor Dashboard")

risk_analysis = {
    'overall_score': 68,
    'risk_level': 'HIGH',
    'component_scores': {
        'configuration': 75,
        'vulnerabilities': 82,
        'files': 45,
        'email': 25
    }
}

st.metric("Overall Risk Score", f"{risk_analysis['overall_score']}/100")
st.metric("Risk Level", risk_analysis["risk_level"])

fig = px.bar(
    x=list(risk_analysis["component_scores"].keys()),
    y=list(risk_analysis["component_scores"].values()),
    title="Component Risk Scores"
)
st.plotly_chart(fig, use_container_width=True)

