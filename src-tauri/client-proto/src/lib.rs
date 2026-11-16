pub mod conversions;
pub mod posture_ext;

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

    pub mod enterprise {
        pub mod posture {
            pub mod v2 {
                tonic::include_proto!("xguard.enterprise.posture.v2");
            }
        }
    }
}
