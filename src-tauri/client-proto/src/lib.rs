pub mod conversions;

pub mod xguard {
    #[allow(clippy::enum_variant_names)]
    pub mod client_types {
        tonic::include_proto!("xguard.client_types");
    }

    pub mod client {
        pub mod v1 {
            tonic::include_proto!("xguard.client.v1");
        }
    }

    pub mod proxy {
        pub mod v1 {
            tonic::include_proto!("xguard.proxy.v1");
        }
    }

}
