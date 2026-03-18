//! CLI guide command family.

use std::io::Read;

use super::mcp_bridge::{build_state, ensure_no_error, print_json, result_json};

pub struct GuideAddOpts<'a> {
    pub name: &'a str,
    pub content: Option<&'a str>,
    pub file: Option<&'a str>,
    pub category: Option<&'a str>,
    pub tags: &'a [String],
    pub status: Option<&'a str>,
    pub related_paths: &'a [String],
    pub json: bool,
}

fn read_guide_content(content: Option<&str>, file: Option<&str>) -> anyhow::Result<String> {
    if let Some(c) = content {
        return Ok(c.to_string());
    }
    if let Some(path) = file {
        return Ok(std::fs::read_to_string(path)?);
    }
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    if buf.trim().is_empty() {
        anyhow::bail!("Guide content is required via --content, --file, or stdin");
    }
    Ok(buf)
}

pub fn guide_get(name: &str, json: bool) -> anyhow::Result<()> {
    let state = build_state()?;
    let value = result_json(vault_mcp::tools::guides::vault_guide(&state, name))?;
    let value = ensure_no_error(value)?;
    if json {
        return print_json(&value);
    }
    println!("{}", value["name"].as_str().unwrap_or(name));
    if let Some(content) = value.get("content").and_then(|v| v.as_str()) {
        println!("{content}");
    } else {
        print_json(&value)?;
    }
    Ok(())
}

pub fn guide_add(opts: GuideAddOpts<'_>) -> anyhow::Result<()> {
    let state = build_state()?;
    let content = read_guide_content(opts.content, opts.file)?;
    let tags = if opts.tags.is_empty() {
        None
    } else {
        Some(opts.tags)
    };
    let related_paths = if opts.related_paths.is_empty() {
        None
    } else {
        Some(opts.related_paths)
    };
    let value = result_json(vault_mcp::tools::guides::vault_add_guide(
        &state,
        opts.name,
        &content,
        opts.category,
        tags,
        opts.status,
        related_paths,
    ))?;
    let value = ensure_no_error(value)?;
    if opts.json {
        return print_json(&value);
    }
    println!("{}", value["message"].as_str().unwrap_or("Guide saved."));
    Ok(())
}

pub fn guide_list(category: Option<&str>, status: Option<&str>, json: bool) -> anyhow::Result<()> {
    let state = build_state()?;
    let value = result_json(vault_mcp::tools::guides::vault_list_guides(
        &state, category, status,
    ))?;
    let value = ensure_no_error(value)?;
    if json {
        return print_json(&value);
    }
    let guides = value["guides"].as_array().cloned().unwrap_or_default();
    if guides.is_empty() {
        println!("No guides found.");
        return Ok(());
    }
    for guide in guides {
        let name = guide["name"].as_str().unwrap_or("-");
        let cat = guide["category"].as_str().unwrap_or("-");
        let stat = guide["status"].as_str().unwrap_or("active");
        println!("{name} [{cat}] ({stat})");
    }
    Ok(())
}

pub fn guide_search(query: &str, json: bool) -> anyhow::Result<()> {
    let state = build_state()?;
    let value = result_json(vault_mcp::tools::guides::vault_search_guides(&state, query))?;
    let value = ensure_no_error(value)?;
    if json {
        return print_json(&value);
    }
    let guides = value["guides"].as_array().cloned().unwrap_or_default();
    if guides.is_empty() {
        println!("No matching guides.");
        return Ok(());
    }
    for guide in guides {
        let name = guide["name"].as_str().unwrap_or("-");
        let cat = guide["category"].as_str().unwrap_or("-");
        println!("{name} [{cat}]");
    }
    Ok(())
}

pub fn guide_delete(name: &str, json: bool) -> anyhow::Result<()> {
    let state = build_state()?;
    let value = result_json(vault_mcp::tools::guides::vault_delete_guide(&state, name))?;
    let value = ensure_no_error(value)?;
    if json {
        return print_json(&value);
    }
    println!("{}", value["message"].as_str().unwrap_or("Guide deleted."));
    Ok(())
}

pub fn guide_verify(name: &str, json: bool) -> anyhow::Result<()> {
    let state = build_state()?;
    let value = result_json(vault_mcp::tools::guides::vault_verify_guide(&state, name))?;
    let value = ensure_no_error(value)?;
    if json {
        return print_json(&value);
    }
    println!("{}", value["message"].as_str().unwrap_or("Guide verified."));
    Ok(())
}

pub fn guide_deprecate(name: &str, json: bool) -> anyhow::Result<()> {
    let state = build_state()?;
    let value = result_json(vault_mcp::tools::guides::vault_deprecate_guide(
        &state, name,
    ))?;
    let value = ensure_no_error(value)?;
    if json {
        return print_json(&value);
    }
    println!(
        "{}",
        value["message"]
            .as_str()
            .unwrap_or("Guide marked deprecated.")
    );
    Ok(())
}

pub fn guide_stale(days: i32, json: bool) -> anyhow::Result<()> {
    let state = build_state()?;
    let value = result_json(vault_mcp::tools::guides::vault_stale_guides(&state, days))?;
    let value = ensure_no_error(value)?;
    if json {
        return print_json(&value);
    }
    let guides = value["guides"].as_array().cloned().unwrap_or_default();
    if guides.is_empty() {
        println!("No stale guides.");
        return Ok(());
    }
    for guide in guides {
        println!("{}", guide["name"].as_str().unwrap_or("-"));
    }
    Ok(())
}
