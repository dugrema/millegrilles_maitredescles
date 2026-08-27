use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::v3::facades::message_inbound::MessageInboundValidator;
use millegrilles_common_rust::v3::MessagingService;

#[async_trait]
pub trait MaitreDesClesSymmetricService {

}

pub struct MaitreDesClesSymmetricServiceImpl {

}

impl MaitreDesClesSymmetricServiceImpl {
    pub fn new(mq: &dyn MessagingService, incoming: &MessageInboundValidator) -> Result<Self, CommonError> {
        let mut service = Self {};
        init_queues(&mut service, mq, incoming)?;
        Ok(service)
    }
}

impl MaitreDesClesSymmetricService for MaitreDesClesSymmetricServiceImpl {
}

fn init_queues(
    service: &mut MaitreDesClesSymmetricServiceImpl,
    mq: &dyn MessagingService,
    incoming: &MessageInboundValidator
) -> Result<(), CommonError> {
    todo!()
}
