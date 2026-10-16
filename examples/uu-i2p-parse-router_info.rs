use std::path::Path;
use uu_i2p::router_info::FullRouterInfo;

fn main() {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: parse_ri <path>");
        eprintln!();
        eprintln!("Reads a RouterInfo file (e.g. from ~/.i2pd/netDb/r*/routerInfo-*.dat)");
        eprintln!("and prints its parsed contents.");
        std::process::exit(1);
    };
    match FullRouterInfo::from_file(Path::new(&path)) {
        Ok(ri) => {
            println!("hash:      {}", ri.ident_hash().to_base64());
            println!("signing:   {:?}", ri.identity().signing_key_type());
            println!("crypto:    {:?}", ri.identity().crypto_key_type());
            println!("timestamp: {}", ri.body().timestamp);
            println!("caps:      {:?}", ri.body().caps);
            println!("version:   {:?}", ri.body().version);
            println!("net_id:    {:?}", ri.body().net_id);
            println!("signature: {} bytes", ri.signature().len());
            println!("addresses: {}", ri.body().addresses.len());
            for (i, a) in ri.body().addresses.iter().enumerate() {
                println!(
                    "  [{}] {} host={} port={} published={} v={} caps=0x{:02x}",
                    i, a.transport_style, a.host, a.port, a.published, a.v, a.caps,
                );
                if let Some(ssu) = &a.ssu {
                    println!(
                        "      ssu.mtu={} introducers={}",
                        ssu.mtu,
                        ssu.introducers.len()
                    );
                }
            }
            println!("props:     {}", ri.body().properties.len());
            for (k, v) in &ri.body().properties {
                println!(
                    "  {:?} = {:?}",
                    String::from_utf8_lossy(k),
                    String::from_utf8_lossy(v)
                );
            }
        }
        Err(e) => {
            eprintln!("parse error: {e}");
            std::process::exit(1);
        }
    }
}
