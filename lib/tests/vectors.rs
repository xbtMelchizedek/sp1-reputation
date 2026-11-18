// Native test: agb-rep reproduces agentwork's supersede-v1 expectations.
use agb_rep::{commit, scenario_view};

#[test]
fn supersede_vectors_native() {
    let p = std::env::var("AGB_VECTORS").unwrap_or("../../agentwork-main/vectors/supersede-v1.json".into());
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&p).expect("set AGB_VECTORS")).unwrap();
    for s in v["scenarios"].as_array().unwrap() {
        let now = s["eval_ts"].as_u64().unwrap();
        let lines: Vec<String> = s["lines"].as_array().unwrap().iter().map(|l| l.as_str().unwrap().to_string()).collect();
        let (tips, counted) = scenario_view(&lines, now);
        assert_eq!(tips, vec![s["expect"]["tip"].as_str().unwrap().to_string()], "{}", s["name"]);
        let c = commit(&lines, now, "");
        assert_eq!(c.droppedMessages, 0, "{}", s["name"]);
        assert_eq!(!counted.is_empty(), s["expect"]["worker_counted"].as_bool().unwrap(), "{}", s["name"]);
    }
}
