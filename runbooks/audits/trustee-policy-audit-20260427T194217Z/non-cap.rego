package policy

import rego.v1

default allow := false

resource_bindings := {
      "flowforge-storage": {
        "repository": "default",
        "tag": "workload-secret-seed",
        "allowed_images": ["ghcr.io/enclava-ai/mini-enclava@sha256:12f2542df53c4886a653136eca90865beeb9eb36f0076b5d407d2f4f1bcf5561", "ghcr.io/enclava-ai/mini-enclava:latest", "nousresearch/hermes-agent:latest", "nousresearch/hermes-agent@sha256:e84543a3240d9fe36d198161c4a4c0455d119d95e6a99a485394a93708555a13", "ghcr.io/enclava-ai/hermes-agent-enclava@sha256:45893f9a40798caa80ccf7dc0d5a011b1c82bfd362d29014a2ae68a149af48d0", "ttl.sh/hermes-agent-enclava-slim-1774815307-24h@sha256:8a5523b8e14726e29a3584646982a3c5c454604342709658bceae342ac715312"],
        "allowed_image_tag_prefixes": ["ghcr.io/enclava-ai/mini-enclava:", "nousresearch/hermes-agent:", "ghcr.io/enclava-ai/hermes-agent-enclava:", "ttl.sh/hermes-agent-enclava-slim-"],
        "allowed_namespaces": ["flowforge", "flowforge-0", "flowforge-1", "flowforge-2"],
        "allowed_service_accounts": ["flowforge-workload"],
        "allowed_init_data_hashes": ["60e963d603eacc7b79b851fc68bcfded2fdfd10cc077f85ec4bda6ba8ef92c79"]
      },
      "flowforge-tls": {
        "repository": "default",
        "tag": "workload-secret-seed",
        "allowed_images": ["ghcr.io/enclava-ai/mini-enclava@sha256:12f2542df53c4886a653136eca90865beeb9eb36f0076b5d407d2f4f1bcf5561", "ghcr.io/enclava-ai/mini-enclava:latest", "nousresearch/hermes-agent:latest", "nousresearch/hermes-agent@sha256:e84543a3240d9fe36d198161c4a4c0455d119d95e6a99a485394a93708555a13", "ghcr.io/enclava-ai/hermes-agent-enclava@sha256:45893f9a40798caa80ccf7dc0d5a011b1c82bfd362d29014a2ae68a149af48d0", "ttl.sh/hermes-agent-enclava-slim-1774815307-24h@sha256:8a5523b8e14726e29a3584646982a3c5c454604342709658bceae342ac715312"],
        "allowed_image_tag_prefixes": ["ghcr.io/enclava-ai/mini-enclava:", "nousresearch/hermes-agent:", "ghcr.io/enclava-ai/hermes-agent-enclava:", "ttl.sh/hermes-agent-enclava-slim-"],
        "allowed_namespaces": ["flowforge", "flowforge-0", "flowforge-1", "flowforge-2"],
        "allowed_service_accounts": ["flowforge-workload"],
        "allowed_init_data_hashes": ["60e963d603eacc7b79b851fc68bcfded2fdfd10cc077f85ec4bda6ba8ef92c79"]
      },
      "flowforge-0-enclava-a-state": {
        "repository": "default",
        "tag": "workload-secret-seed",
        "allowed_images": ["ghcr.io/enclava-ai/mini-enclava@sha256:12f2542df53c4886a653136eca90865beeb9eb36f0076b5d407d2f4f1bcf5561", "ghcr.io/enclava-ai/mini-enclava:latest", "nousresearch/hermes-agent:latest", "nousresearch/hermes-agent@sha256:e84543a3240d9fe36d198161c4a4c0455d119d95e6a99a485394a93708555a13", "ghcr.io/enclava-ai/hermes-agent-enclava@sha256:45893f9a40798caa80ccf7dc0d5a011b1c82bfd362d29014a2ae68a149af48d0", "ttl.sh/hermes-agent-enclava-slim-1774815307-24h@sha256:8a5523b8e14726e29a3584646982a3c5c454604342709658bceae342ac715312"],
        "allowed_image_tag_prefixes": ["ghcr.io/enclava-ai/mini-enclava:", "nousresearch/hermes-agent:", "ghcr.io/enclava-ai/hermes-agent-enclava:", "ttl.sh/hermes-agent-enclava-slim-"],
        "allowed_namespaces": ["flowforge-0"],
        "allowed_service_accounts": ["flowforge-workload"],
        "allowed_init_data_hashes": ["60e963d603eacc7b79b851fc68bcfded2fdfd10cc077f85ec4bda6ba8ef92c79"]
      },
      "flowforge-0-enclava-a-tls": {
        "repository": "default",
        "tag": "workload-secret-seed",
        "allowed_images": ["ghcr.io/enclava-ai/mini-enclava@sha256:12f2542df53c4886a653136eca90865beeb9eb36f0076b5d407d2f4f1bcf5561", "ghcr.io/enclava-ai/mini-enclava:latest", "nousresearch/hermes-agent:latest", "nousresearch/hermes-agent@sha256:e84543a3240d9fe36d198161c4a4c0455d119d95e6a99a485394a93708555a13", "ghcr.io/enclava-ai/hermes-agent-enclava@sha256:45893f9a40798caa80ccf7dc0d5a011b1c82bfd362d29014a2ae68a149af48d0", "ttl.sh/hermes-agent-enclava-slim-1774815307-24h@sha256:8a5523b8e14726e29a3584646982a3c5c454604342709658bceae342ac715312"],
        "allowed_image_tag_prefixes": ["ghcr.io/enclava-ai/mini-enclava:", "nousresearch/hermes-agent:", "ghcr.io/enclava-ai/hermes-agent-enclava:", "ttl.sh/hermes-agent-enclava-slim-"],
        "allowed_namespaces": ["flowforge-0"],
        "allowed_service_accounts": ["flowforge-workload"],
        "allowed_init_data_hashes": ["60e963d603eacc7b79b851fc68bcfded2fdfd10cc077f85ec4bda6ba8ef92c79"]
      },
      "flowforge-0-enclava-b-state": {
        "repository": "default",
        "tag": "workload-secret-seed",
        "allowed_images": ["ghcr.io/enclava-ai/mini-enclava@sha256:12f2542df53c4886a653136eca90865beeb9eb36f0076b5d407d2f4f1bcf5561", "ghcr.io/enclava-ai/mini-enclava:latest", "nousresearch/hermes-agent:latest", "nousresearch/hermes-agent@sha256:e84543a3240d9fe36d198161c4a4c0455d119d95e6a99a485394a93708555a13", "ghcr.io/enclava-ai/hermes-agent-enclava@sha256:45893f9a40798caa80ccf7dc0d5a011b1c82bfd362d29014a2ae68a149af48d0", "ttl.sh/hermes-agent-enclava-slim-1774815307-24h@sha256:8a5523b8e14726e29a3584646982a3c5c454604342709658bceae342ac715312"],
        "allowed_image_tag_prefixes": ["ghcr.io/enclava-ai/mini-enclava:", "nousresearch/hermes-agent:", "ghcr.io/enclava-ai/hermes-agent-enclava:", "ttl.sh/hermes-agent-enclava-slim-"],
        "allowed_namespaces": ["flowforge-0"],
        "allowed_service_accounts": ["flowforge-workload"],
        "allowed_init_data_hashes": ["60e963d603eacc7b79b851fc68bcfded2fdfd10cc077f85ec4bda6ba8ef92c79"]
      },
      "flowforge-0-enclava-b-tls": {
        "repository": "default",
        "tag": "workload-secret-seed",
        "allowed_images": ["ghcr.io/enclava-ai/mini-enclava@sha256:12f2542df53c4886a653136eca90865beeb9eb36f0076b5d407d2f4f1bcf5561", "ghcr.io/enclava-ai/mini-enclava:latest", "nousresearch/hermes-agent:latest", "nousresearch/hermes-agent@sha256:e84543a3240d9fe36d198161c4a4c0455d119d95e6a99a485394a93708555a13", "ghcr.io/enclava-ai/hermes-agent-enclava@sha256:45893f9a40798caa80ccf7dc0d5a011b1c82bfd362d29014a2ae68a149af48d0", "ttl.sh/hermes-agent-enclava-slim-1774815307-24h@sha256:8a5523b8e14726e29a3584646982a3c5c454604342709658bceae342ac715312"],
        "allowed_image_tag_prefixes": ["ghcr.io/enclava-ai/mini-enclava:", "nousresearch/hermes-agent:", "ghcr.io/enclava-ai/hermes-agent-enclava:", "ttl.sh/hermes-agent-enclava-slim-"],
        "allowed_namespaces": ["flowforge-0"],
        "allowed_service_accounts": ["flowforge-workload"],
        "allowed_init_data_hashes": ["60e963d603eacc7b79b851fc68bcfded2fdfd10cc077f85ec4bda6ba8ef92c79"]
      },
      "flowforge-1-enclava-a-state": {
        "repository": "default",
        "tag": "workload-secret-seed",
        "allowed_images": ["ghcr.io/enclava-ai/mini-enclava@sha256:12f2542df53c4886a653136eca90865beeb9eb36f0076b5d407d2f4f1bcf5561", "ghcr.io/enclava-ai/mini-enclava:latest", "nousresearch/hermes-agent:latest", "nousresearch/hermes-agent@sha256:e84543a3240d9fe36d198161c4a4c0455d119d95e6a99a485394a93708555a13", "ghcr.io/enclava-ai/hermes-agent-enclava@sha256:45893f9a40798caa80ccf7dc0d5a011b1c82bfd362d29014a2ae68a149af48d0", "ttl.sh/hermes-agent-enclava-slim-1774815307-24h@sha256:8a5523b8e14726e29a3584646982a3c5c454604342709658bceae342ac715312"],
        "allowed_image_tag_prefixes": ["ghcr.io/enclava-ai/mini-enclava:", "nousresearch/hermes-agent:", "ghcr.io/enclava-ai/hermes-agent-enclava:", "ttl.sh/hermes-agent-enclava-slim-"],
        "allowed_namespaces": ["flowforge-1"],
        "allowed_service_accounts": ["flowforge-workload"],
        "allowed_init_data_hashes": ["60e963d603eacc7b79b851fc68bcfded2fdfd10cc077f85ec4bda6ba8ef92c79"]
      },
      "flowforge-1-enclava-a-tls": {
        "repository": "default",
        "tag": "workload-secret-seed",
        "allowed_images": ["ghcr.io/enclava-ai/mini-enclava@sha256:12f2542df53c4886a653136eca90865beeb9eb36f0076b5d407d2f4f1bcf5561", "ghcr.io/enclava-ai/mini-enclava:latest", "nousresearch/hermes-agent:latest", "nousresearch/hermes-agent@sha256:e84543a3240d9fe36d198161c4a4c0455d119d95e6a99a485394a93708555a13", "ghcr.io/enclava-ai/hermes-agent-enclava@sha256:45893f9a40798caa80ccf7dc0d5a011b1c82bfd362d29014a2ae68a149af48d0", "ttl.sh/hermes-agent-enclava-slim-1774815307-24h@sha256:8a5523b8e14726e29a3584646982a3c5c454604342709658bceae342ac715312"],
        "allowed_image_tag_prefixes": ["ghcr.io/enclava-ai/mini-enclava:", "nousresearch/hermes-agent:", "ghcr.io/enclava-ai/hermes-agent-enclava:", "ttl.sh/hermes-agent-enclava-slim-"],
        "allowed_namespaces": ["flowforge-1"],
        "allowed_service_accounts": ["flowforge-workload"],
        "allowed_init_data_hashes": ["60e963d603eacc7b79b851fc68bcfded2fdfd10cc077f85ec4bda6ba8ef92c79"]
      },
      "flowforge-1-enclava-b-state": {
        "repository": "default",
        "tag": "workload-secret-seed",
        "allowed_images": ["ghcr.io/enclava-ai/mini-enclava@sha256:12f2542df53c4886a653136eca90865beeb9eb36f0076b5d407d2f4f1bcf5561", "ghcr.io/enclava-ai/mini-enclava:latest", "nousresearch/hermes-agent:latest", "nousresearch/hermes-agent@sha256:e84543a3240d9fe36d198161c4a4c0455d119d95e6a99a485394a93708555a13", "ghcr.io/enclava-ai/hermes-agent-enclava@sha256:45893f9a40798caa80ccf7dc0d5a011b1c82bfd362d29014a2ae68a149af48d0", "ttl.sh/hermes-agent-enclava-slim-1774815307-24h@sha256:8a5523b8e14726e29a3584646982a3c5c454604342709658bceae342ac715312"],
        "allowed_image_tag_prefixes": ["ghcr.io/enclava-ai/mini-enclava:", "nousresearch/hermes-agent:", "ghcr.io/enclava-ai/hermes-agent-enclava:", "ttl.sh/hermes-agent-enclava-slim-"],
        "allowed_namespaces": ["flowforge-1"],
        "allowed_service_accounts": ["flowforge-workload"],
        "allowed_init_data_hashes": ["60e963d603eacc7b79b851fc68bcfded2fdfd10cc077f85ec4bda6ba8ef92c79"]
      },
      "flowforge-1-enclava-b-tls": {
        "repository": "default",
        "tag": "workload-secret-seed",
        "allowed_images": ["ghcr.io/enclava-ai/mini-enclava@sha256:12f2542df53c4886a653136eca90865beeb9eb36f0076b5d407d2f4f1bcf5561", "ghcr.io/enclava-ai/mini-enclava:latest", "nousresearch/hermes-agent:latest", "nousresearch/hermes-agent@sha256:e84543a3240d9fe36d198161c4a4c0455d119d95e6a99a485394a93708555a13", "ghcr.io/enclava-ai/hermes-agent-enclava@sha256:45893f9a40798caa80ccf7dc0d5a011b1c82bfd362d29014a2ae68a149af48d0", "ttl.sh/hermes-agent-enclava-slim-1774815307-24h@sha256:8a5523b8e14726e29a3584646982a3c5c454604342709658bceae342ac715312"],
        "allowed_image_tag_prefixes": ["ghcr.io/enclava-ai/mini-enclava:", "nousresearch/hermes-agent:", "ghcr.io/enclava-ai/hermes-agent-enclava:", "ttl.sh/hermes-agent-enclava-slim-"],
        "allowed_namespaces": ["flowforge-1"],
        "allowed_service_accounts": ["flowforge-workload"],
        "allowed_init_data_hashes": ["60e963d603eacc7b79b851fc68bcfded2fdfd10cc077f85ec4bda6ba8ef92c79"]
      },
      "flowforge-1-auto-1-state": {
        "repository": "default",
        "tag": "workload-secret-seed",
        "allowed_images": ["ghcr.io/enclava-ai/mini-enclava@sha256:12f2542df53c4886a653136eca90865beeb9eb36f0076b5d407d2f4f1bcf5561", "ghcr.io/enclava-ai/mini-enclava:latest", "nousresearch/hermes-agent:latest", "nousresearch/hermes-agent@sha256:e84543a3240d9fe36d198161c4a4c0455d119d95e6a99a485394a93708555a13", "ghcr.io/enclava-ai/hermes-agent-enclava@sha256:45893f9a40798caa80ccf7dc0d5a011b1c82bfd362d29014a2ae68a149af48d0", "ttl.sh/hermes-agent-enclava-slim-1774815307-24h@sha256:8a5523b8e14726e29a3584646982a3c5c454604342709658bceae342ac715312"],
        "allowed_image_tag_prefixes": ["ghcr.io/enclava-ai/mini-enclava:", "nousresearch/hermes-agent:", "ghcr.io/enclava-ai/hermes-agent-enclava:", "ttl.sh/hermes-agent-enclava-slim-"],
        "allowed_namespaces": ["flowforge-1"],
        "allowed_service_accounts": ["flowforge-workload"],
        "allowed_init_data_hashes": ["60e963d603eacc7b79b851fc68bcfded2fdfd10cc077f85ec4bda6ba8ef92c79"]
      },
      "flowforge-1-auto-1-tls": {
        "repository": "default",
        "tag": "workload-secret-seed",
        "allowed_images": ["ghcr.io/enclava-ai/mini-enclava@sha256:12f2542df53c4886a653136eca90865beeb9eb36f0076b5d407d2f4f1bcf5561", "ghcr.io/enclava-ai/mini-enclava:latest", "nousresearch/hermes-agent:latest", "nousresearch/hermes-agent@sha256:e84543a3240d9fe36d198161c4a4c0455d119d95e6a99a485394a93708555a13", "ghcr.io/enclava-ai/hermes-agent-enclava@sha256:45893f9a40798caa80ccf7dc0d5a011b1c82bfd362d29014a2ae68a149af48d0", "ttl.sh/hermes-agent-enclava-slim-1774815307-24h@sha256:8a5523b8e14726e29a3584646982a3c5c454604342709658bceae342ac715312"],
        "allowed_image_tag_prefixes": ["ghcr.io/enclava-ai/mini-enclava:", "nousresearch/hermes-agent:", "ghcr.io/enclava-ai/hermes-agent-enclava:", "ttl.sh/hermes-agent-enclava-slim-"],
        "allowed_namespaces": ["flowforge-1"],
        "allowed_service_accounts": ["flowforge-workload"],
        "allowed_init_data_hashes": ["60e963d603eacc7b79b851fc68bcfded2fdfd10cc077f85ec4bda6ba8ef92c79"]
      },
      "flowforge-1-hermes-agent-4-state": {
        "repository": "default",
        "tag": "workload-secret-seed",
        "allowed_images": ["ghcr.io/enclava-ai/mini-enclava@sha256:12f2542df53c4886a653136eca90865beeb9eb36f0076b5d407d2f4f1bcf5561", "ghcr.io/enclava-ai/mini-enclava:latest", "nousresearch/hermes-agent:latest", "nousresearch/hermes-agent@sha256:e84543a3240d9fe36d198161c4a4c0455d119d95e6a99a485394a93708555a13", "ghcr.io/enclava-ai/hermes-agent-enclava@sha256:45893f9a40798caa80ccf7dc0d5a011b1c82bfd362d29014a2ae68a149af48d0", "ttl.sh/hermes-agent-enclava-slim-1774815307-24h@sha256:8a5523b8e14726e29a3584646982a3c5c454604342709658bceae342ac715312"],
        "allowed_image_tag_prefixes": ["ghcr.io/enclava-ai/mini-enclava:", "nousresearch/hermes-agent:", "ghcr.io/enclava-ai/hermes-agent-enclava:", "ttl.sh/hermes-agent-enclava-slim-"],
        "allowed_namespaces": ["flowforge-1"],
        "allowed_service_accounts": ["flowforge-workload"],
        "allowed_init_data_hashes": ["60e963d603eacc7b79b851fc68bcfded2fdfd10cc077f85ec4bda6ba8ef92c79"]
      },
      "flowforge-1-hermes-agent-4-tls": {
        "repository": "default",
        "tag": "workload-secret-seed",
        "allowed_images": ["ghcr.io/enclava-ai/mini-enclava@sha256:12f2542df53c4886a653136eca90865beeb9eb36f0076b5d407d2f4f1bcf5561", "ghcr.io/enclava-ai/mini-enclava:latest", "nousresearch/hermes-agent:latest", "nousresearch/hermes-agent@sha256:e84543a3240d9fe36d198161c4a4c0455d119d95e6a99a485394a93708555a13", "ghcr.io/enclava-ai/hermes-agent-enclava@sha256:45893f9a40798caa80ccf7dc0d5a011b1c82bfd362d29014a2ae68a149af48d0", "ttl.sh/hermes-agent-enclava-slim-1774815307-24h@sha256:8a5523b8e14726e29a3584646982a3c5c454604342709658bceae342ac715312"],
        "allowed_image_tag_prefixes": ["ghcr.io/enclava-ai/mini-enclava:", "nousresearch/hermes-agent:", "ghcr.io/enclava-ai/hermes-agent-enclava:", "ttl.sh/hermes-agent-enclava-slim-"],
        "allowed_namespaces": ["flowforge-1"],
        "allowed_service_accounts": ["flowforge-workload"],
        "allowed_init_data_hashes": ["60e963d603eacc7b79b851fc68bcfded2fdfd10cc077f85ec4bda6ba8ef92c79"]
      },
      "flowforge-2-enclava-a-state": {
        "repository": "default",
        "tag": "workload-secret-seed",
        "allowed_images": ["ghcr.io/enclava-ai/mini-enclava@sha256:12f2542df53c4886a653136eca90865beeb9eb36f0076b5d407d2f4f1bcf5561", "ghcr.io/enclava-ai/mini-enclava:latest", "nousresearch/hermes-agent:latest", "nousresearch/hermes-agent@sha256:e84543a3240d9fe36d198161c4a4c0455d119d95e6a99a485394a93708555a13", "ghcr.io/enclava-ai/hermes-agent-enclava@sha256:45893f9a40798caa80ccf7dc0d5a011b1c82bfd362d29014a2ae68a149af48d0", "ttl.sh/hermes-agent-enclava-slim-1774815307-24h@sha256:8a5523b8e14726e29a3584646982a3c5c454604342709658bceae342ac715312"],
        "allowed_image_tag_prefixes": ["ghcr.io/enclava-ai/mini-enclava:", "nousresearch/hermes-agent:", "ghcr.io/enclava-ai/hermes-agent-enclava:", "ttl.sh/hermes-agent-enclava-slim-"],
        "allowed_namespaces": ["flowforge-2"],
        "allowed_service_accounts": ["flowforge-workload"],
        "allowed_init_data_hashes": ["60e963d603eacc7b79b851fc68bcfded2fdfd10cc077f85ec4bda6ba8ef92c79"]
      },
      "flowforge-2-enclava-a-tls": {
        "repository": "default",
        "tag": "workload-secret-seed",
        "allowed_images": ["ghcr.io/enclava-ai/mini-enclava@sha256:12f2542df53c4886a653136eca90865beeb9eb36f0076b5d407d2f4f1bcf5561", "ghcr.io/enclava-ai/mini-enclava:latest", "nousresearch/hermes-agent:latest", "nousresearch/hermes-agent@sha256:e84543a3240d9fe36d198161c4a4c0455d119d95e6a99a485394a93708555a13", "ghcr.io/enclava-ai/hermes-agent-enclava@sha256:45893f9a40798caa80ccf7dc0d5a011b1c82bfd362d29014a2ae68a149af48d0", "ttl.sh/hermes-agent-enclava-slim-1774815307-24h@sha256:8a5523b8e14726e29a3584646982a3c5c454604342709658bceae342ac715312"],
        "allowed_image_tag_prefixes": ["ghcr.io/enclava-ai/mini-enclava:", "nousresearch/hermes-agent:", "ghcr.io/enclava-ai/hermes-agent-enclava:", "ttl.sh/hermes-agent-enclava-slim-"],
        "allowed_namespaces": ["flowforge-2"],
        "allowed_service_accounts": ["flowforge-workload"],
        "allowed_init_data_hashes": ["60e963d603eacc7b79b851fc68bcfded2fdfd10cc077f85ec4bda6ba8ef92c79"]
      },
      "flowforge-2-enclava-b-state": {
        "repository": "default",
        "tag": "workload-secret-seed",
        "allowed_images": ["ghcr.io/enclava-ai/mini-enclava@sha256:12f2542df53c4886a653136eca90865beeb9eb36f0076b5d407d2f4f1bcf5561", "ghcr.io/enclava-ai/mini-enclava:latest", "nousresearch/hermes-agent:latest", "nousresearch/hermes-agent@sha256:e84543a3240d9fe36d198161c4a4c0455d119d95e6a99a485394a93708555a13", "ghcr.io/enclava-ai/hermes-agent-enclava@sha256:45893f9a40798caa80ccf7dc0d5a011b1c82bfd362d29014a2ae68a149af48d0", "ttl.sh/hermes-agent-enclava-slim-1774815307-24h@sha256:8a5523b8e14726e29a3584646982a3c5c454604342709658bceae342ac715312"],
        "allowed_image_tag_prefixes": ["ghcr.io/enclava-ai/mini-enclava:", "nousresearch/hermes-agent:", "ghcr.io/enclava-ai/hermes-agent-enclava:", "ttl.sh/hermes-agent-enclava-slim-"],
        "allowed_namespaces": ["flowforge-2"],
        "allowed_service_accounts": ["flowforge-workload"],
        "allowed_init_data_hashes": ["60e963d603eacc7b79b851fc68bcfded2fdfd10cc077f85ec4bda6ba8ef92c79"]
      },
      "flowforge-2-enclava-b-tls": {
        "repository": "default",
        "tag": "workload-secret-seed",
        "allowed_images": ["ghcr.io/enclava-ai/mini-enclava@sha256:12f2542df53c4886a653136eca90865beeb9eb36f0076b5d407d2f4f1bcf5561", "ghcr.io/enclava-ai/mini-enclava:latest", "nousresearch/hermes-agent:latest", "nousresearch/hermes-agent@sha256:e84543a3240d9fe36d198161c4a4c0455d119d95e6a99a485394a93708555a13", "ghcr.io/enclava-ai/hermes-agent-enclava@sha256:45893f9a40798caa80ccf7dc0d5a011b1c82bfd362d29014a2ae68a149af48d0", "ttl.sh/hermes-agent-enclava-slim-1774815307-24h@sha256:8a5523b8e14726e29a3584646982a3c5c454604342709658bceae342ac715312"],
        "allowed_image_tag_prefixes": ["ghcr.io/enclava-ai/mini-enclava:", "nousresearch/hermes-agent:", "ghcr.io/enclava-ai/hermes-agent-enclava:", "ttl.sh/hermes-agent-enclava-slim-"],
        "allowed_namespaces": ["flowforge-2"],
        "allowed_service_accounts": ["flowforge-workload"],
        "allowed_init_data_hashes": ["60e963d603eacc7b79b851fc68bcfded2fdfd10cc077f85ec4bda6ba8ef92c79"]
      },
      "zeroclaw-storage": {
        "repository": "default",
        "tag": "workload-secret-seed",
        "allowed_images": ["ghcr.io/enclava-ai/zeroclaw-confidential@sha256:0f1ead76d59cbdd82691c7cf803ee20fff670cb1eccdc98dcf8a196c43dac5af", "ghcr.io/enclava-ai/zeroclaw-confidential:latest"],
        "allowed_image_tag_prefixes": ["ghcr.io/enclava-ai/zeroclaw-confidential:"],
        "allowed_namespaces": ["flowforge", "flowforge-0", "flowforge-1", "flowforge-2", "zeroclaw-01"],
        "allowed_service_accounts": ["zeroclaw-l01-workload", "zeroclaw-01-workload"],
        "allowed_init_data_hashes": ["2c48bfcbbacea1799c15c340476cedbc1365290734f6281083298b87cc03554c"]
      },
      "postgresql-demo-storage": {
        "repository": "default",
        "tag": "workload-secret-seed",
        "allowed_images": ["ghcr.io/aljazceru/nutshell-tee@sha256:9ae0bf9a7d93b1da2c6ac7f95ba6935bb60a99b11589286fa10648dfb8f0e7c2"],
        "allowed_image_tag_prefixes": ["ghcr.io/aljazceru/nutshell-tee:"],
        "allowed_namespaces": ["postgresql-demo"],
        "allowed_service_accounts": ["postgresql-workload"],
        "allowed_init_data_hashes": ["2c48bfcbbacea1799c15c340476cedbc1365290734f6281083298b87cc03554c"]
      },
      "redis-demo-storage": {
        "repository": "default",
        "tag": "workload-secret-seed",
        "allowed_images": ["ghcr.io/aljazceru/nutshell-tee@sha256:14cbd0bca3b3a246234133f6d192adb16095063b9536790ebbe30b88c1ca7f1a"],
        "allowed_image_tag_prefixes": ["ghcr.io/aljazceru/nutshell-tee:"],
        "allowed_namespaces": ["redis-demo"],
        "allowed_service_accounts": ["redis-workload"],
        "allowed_init_data_hashes": ["cd3438a42fcfae5a8af41052e62df1578823e78b57110f44371f96747b7ce9b5"]
      }
    ,
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  

















































}

owner_resource_bindings := {
      "flowforge-1-ot-1-owner": {
        "repository": "default",
        "allowed_tags": ["seed-encrypted", "seed-sealed"],
        "allowed_namespaces": ["flowforge-1"],
        "allowed_service_accounts": ["flowforge-workload"],
        "allowed_identity_hashes": ["df0cf721a6c2c3f31798d8e08fdb1f9643bf35dcf70d7c274d32ef706c433dc8"]
      },
      "flowforge-1-ot-2-owner": {
        "repository": "default",
        "allowed_tags": ["seed-encrypted", "seed-sealed"],
        "allowed_namespaces": ["flowforge-1"],
        "allowed_service_accounts": ["flowforge-workload"],
        "allowed_identity_hashes": ["6150552a334c8cf69a3736cca452daa002a25c4eb775f9de5c3c823a15e49aa2"]
      },
      "flowforge-1-mini-canary-owner": {
        "repository": "default",
        "allowed_tags": ["seed-encrypted", "seed-sealed"],
        "allowed_namespaces": ["flowforge-1"],
        "allowed_service_accounts": ["flowforge-workload"],
        "allowed_identity_hashes": ["ae150a2feba4c0f85526e93c8206675a07d1bd7e1fb89f67c6d551b04d218dcf"]
      },
      "flowforge-1-mini-canary-2-owner": {
        "repository": "default",
        "allowed_tags": ["seed-encrypted", "seed-sealed"],
        "allowed_namespaces": ["flowforge-1"],
        "allowed_service_accounts": ["flowforge-workload"],
        "allowed_identity_hashes": ["5b52f1ff23ba494094eb5861050552267f33cf9e64363636ef5eaf3bfc313f2c"]
      },
      "flowforge-1-mini-canary-auto-owner": {
        "repository": "default",
        "allowed_tags": ["seed-encrypted", "seed-sealed"],
        "allowed_namespaces": ["flowforge-1"],
        "allowed_service_accounts": ["flowforge-workload"],
        "allowed_identity_hashes": ["a489b01160e4e7194e6eec35dd62b288ce2de6bbc15334f24baa8a851f85662c"]
      }
    ,
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  


























































































}

    # KBS may pass resource-path as either:
    #   1) "resource/<repository>/<resource-name>/<tag>" (string)
    #   2) ["<repository>", "<resource-name>", "<tag>"] (array)
    requested_path := path if {
      rp := data["resource-path"]
      is_string(rp)
      path := split(rp, "/")
    }

    requested_path := path if {
      rp := data["resource-path"]
      is_array(rp)
      path := rp
    }

    requested_binding := binding if {
      count(requested_path) == 4
      requested_path[0] == "resource"
      binding := resource_bindings[requested_path[2]]
      requested_path[1] == binding.repository
      requested_path[3] == binding.tag
    }

    requested_binding := binding if {
      count(requested_path) == 3
      binding := resource_bindings[requested_path[1]]
      requested_path[0] == binding.repository
      requested_path[2] == binding.tag
    }

    container_image_name(container) := image if {
      image := container["OCI"]["Annotations"]["io.kubernetes.cri.image-name"]
      is_string(image)
      image != ""
    }

    container_image_name(container) := image if {
      image := container["image_name"]
      is_string(image)
      image != ""
    }

    container_image_name(container) := image if {
      image := container["Image"]
      is_string(image)
      image != ""
    }

    container_image_name(container) := image if {
      image := container["image"]
      is_string(image)
      image != ""
    }

    container_annotation(container, key) := value if {
      oci := object.get(container, "OCI", {})
      ann := object.get(oci, "Annotations", {})
      value := object.get(ann, key, "")
      is_string(value)
      value != ""
    }

    # EAR/JWT shapes vary; collect workload containers from all known locations (KBS OPA input).
    pods_containers contains container if {
      cpu0 := object.get(object.get(input, "submods", {}), "cpu0", {})
      ev := object.get(cpu0, "ear.veraison.annotated-evidence", {})
      idc := object.get(ev, "init_data_claims", {})
      apc := object.get(idc, "agent_policy_claims", {})
      containers := object.get(apc, "containers", [])
      is_array(containers)
      container := containers[_]
    }

    pods_containers contains container if {
      cpu0 := object.get(object.get(input, "submods", {}), "cpu0", {})
      idc := object.get(cpu0, "ear.veraison.annotated-evidence.init_data_claims", {})
      apc := object.get(idc, "agent_policy_claims", {})
      containers := object.get(apc, "containers", [])
      is_array(containers)
      container := containers[_]
    }

    pods_containers contains container if {
      idc := object.get(input, "init_data_claims", {})
      apc := object.get(idc, "agent_policy_claims", {})
      containers := object.get(apc, "containers", [])
      is_array(containers)
      container := containers[_]
    }

    pods_containers contains container if {
      cpu0 := object.get(object.get(input, "submods", {}), "cpu0", {})
      idc := object.get(cpu0, "init_data_claims", {})
      apc := object.get(idc, "agent_policy_claims", {})
      containers := object.get(apc, "containers", [])
      is_array(containers)
      container := containers[_]
    }

    # EAR tokens may carry pod/container identity under runtime_data_claims (tee-pubkey path uses this).
    pods_containers contains container if {
      cpu0 := object.get(object.get(input, "submods", {}), "cpu0", {})
      ev := object.get(cpu0, "ear.veraison.annotated-evidence", {})
      rdc := object.get(ev, "runtime_data_claims", {})
      apc := object.get(rdc, "agent_policy_claims", {})
      containers := object.get(apc, "containers", [])
      is_array(containers)
      container := containers[_]
    }

    requester_images contains image if {
      container := pods_containers[_]
      image := lower(container_image_name(container))
      image != ""
    }

    # CoCo may expose validated workload images here instead of full init_data_claims.containers
    # (see confidential-containers/trustee integration-tests/tests/init_data.rs).
    requester_images contains image if {
      cpu0 := object.get(object.get(input, "submods", {}), "cpu0", {})
      tid := object.get(cpu0, "ear.trustee.identifiers", {})
      val := object.get(tid, "validated", {})
      imgs := object.get(val, "container_images", [])
      is_array(imgs)
      raw := imgs[_]
      is_string(raw)
      image := lower(raw)
      image != ""
    }

    requester_images_present if {
      count(requester_images) > 0
    }

    requester_namespaces contains ns if {
      container := pods_containers[_]
      ns := lower(container_annotation(container, "io.kubernetes.pod.namespace"))
      ns != ""
    }

    requester_namespaces_present if {
      count(requester_namespaces) > 0
    }

    requester_service_accounts contains sa if {
      container := pods_containers[_]
      sa := lower(container_annotation(container, "io.kubernetes.pod.service-account.name"))
      sa != ""
    }

    requester_service_accounts_present if {
      count(requester_service_accounts) > 0
    }

    requester_instances contains inst if {
      container := pods_containers[_]
      inst := lower(container_annotation(container, "tenant.flowforge.sh/instance"))
      inst != ""
    }

    requester_init_data_hashes contains hash if {
      cpu0 := object.get(object.get(input, "submods", {}), "cpu0", {})
      ev := object.get(cpu0, "ear.veraison.annotated-evidence", {})
      raw := object.get(ev, "init_data", "")
      is_string(raw)
      raw != ""
      hash := lower(raw)
    }

    requester_init_data_hashes contains hash if {
      cpu0 := object.get(object.get(input, "submods", {}), "cpu0", {})
      raw := object.get(cpu0, "ear.veraison.annotated-evidence.init_data", "")
      is_string(raw)
      raw != ""
      hash := lower(raw)
    }

    requester_init_data_hashes contains hash if {
      raw := object.get(input, "init_data", "")
      is_string(raw)
      raw != ""
      hash := lower(raw)
    }

    requester_init_data_present if {
      count(requester_init_data_hashes) > 0
    }

    # ============================================================================
    # Ownership mode: stable identity hash binding (Phase 1)
    # WARNING: EAR token claim path needs validation against real attestation output.
    # Multiple extraction paths are attempted to handle token format variations.
    # TODO(phase-1-deploy): Capture real EAR token, confirm which path works, remove dead paths.
    # ============================================================================

    # Attempt 1: via init_data_claims.identity (if custom TOML data entries are parsed)
    requester_identity_hashes contains hash if {
      cpu0 := object.get(object.get(input, "submods", {}), "cpu0", {})
      ev := object.get(cpu0, "ear.veraison.annotated-evidence", {})
      idc := object.get(ev, "init_data_claims", {})
      identity := object.get(idc, "identity", {})
      raw := object.get(identity, "tenant_instance_identity_hash", "")
      is_string(raw)
      raw != ""
      hash := lower(raw)
    }

    # Attempt 2: via init_data_claims top-level (flattened)
    requester_identity_hashes contains hash if {
      cpu0 := object.get(object.get(input, "submods", {}), "cpu0", {})
      ev := object.get(cpu0, "ear.veraison.annotated-evidence", {})
      idc := object.get(ev, "init_data_claims", {})
      raw := object.get(idc, "tenant_instance_identity_hash", "")
      is_string(raw)
      raw != ""
      hash := lower(raw)
    }

    # Attempt 3: via flattened dot-path (some CoCo versions)
    requester_identity_hashes contains hash if {
      cpu0 := object.get(object.get(input, "submods", {}), "cpu0", {})
      idc := object.get(cpu0, "ear.veraison.annotated-evidence.init_data_claims", {})
      raw := object.get(idc, "tenant_instance_identity_hash", "")
      is_string(raw)
      raw != ""
      hash := lower(raw)
    }

    # Attempt 4: via raw identity.toml string embedded in init_data_claims.
    # Live AA Bearer tokens currently ship ownership identity claims this way.
    requester_identity_hashes contains hash if {
      cpu0 := object.get(object.get(input, "submods", {}), "cpu0", {})
      ev := object.get(cpu0, "ear.veraison.annotated-evidence", {})
      idc := object.get(ev, "init_data_claims", {})
      identity_toml := object.get(idc, "identity.toml", "")
      is_string(identity_toml)
      some line in split(identity_toml, "\n")
      trimmed := trim(line, " \t\r")
      parts := split(trimmed, "\"")
      count(parts) >= 2
      trim(parts[0], " \t") == "tenant_instance_identity_hash ="
      raw := parts[1]
      raw != ""
      hash := lower(raw)
    }

    requester_tenant_ids contains tenant if {
      cpu0 := object.get(object.get(input, "submods", {}), "cpu0", {})
      ev := object.get(cpu0, "ear.veraison.annotated-evidence", {})
      idc := object.get(ev, "init_data_claims", {})
      identity := object.get(idc, "identity", {})
      raw := object.get(identity, "tenant_id", "")
      is_string(raw)
      raw != ""
      tenant := lower(raw)
    }

    requester_tenant_ids contains tenant if {
      cpu0 := object.get(object.get(input, "submods", {}), "cpu0", {})
      ev := object.get(cpu0, "ear.veraison.annotated-evidence", {})
      idc := object.get(ev, "init_data_claims", {})
      raw := object.get(idc, "tenant_id", "")
      is_string(raw)
      raw != ""
      tenant := lower(raw)
    }

    requester_tenant_ids contains tenant if {
      cpu0 := object.get(object.get(input, "submods", {}), "cpu0", {})
      idc := object.get(cpu0, "ear.veraison.annotated-evidence.init_data_claims", {})
      raw := object.get(idc, "tenant_id", "")
      is_string(raw)
      raw != ""
      tenant := lower(raw)
    }

    requester_tenant_ids contains tenant if {
      cpu0 := object.get(object.get(input, "submods", {}), "cpu0", {})
      ev := object.get(cpu0, "ear.veraison.annotated-evidence", {})
      idc := object.get(ev, "init_data_claims", {})
      identity_toml := object.get(idc, "identity.toml", "")
      is_string(identity_toml)
      some line in split(identity_toml, "\n")
      trimmed := trim(line, " \t\r")
      parts := split(trimmed, "\"")
      count(parts) >= 2
      trim(parts[0], " \t") == "tenant_id ="
      raw := parts[1]
      raw != ""
      tenant := lower(raw)
    }

    requester_tenant_ids_present if {
      count(requester_tenant_ids) > 0
    }

    requester_identity_instance_ids contains inst if {
      cpu0 := object.get(object.get(input, "submods", {}), "cpu0", {})
      ev := object.get(cpu0, "ear.veraison.annotated-evidence", {})
      idc := object.get(ev, "init_data_claims", {})
      identity := object.get(idc, "identity", {})
      raw := object.get(identity, "instance_id", "")
      is_string(raw)
      raw != ""
      inst := lower(raw)
    }

    requester_identity_instance_ids contains inst if {
      cpu0 := object.get(object.get(input, "submods", {}), "cpu0", {})
      ev := object.get(cpu0, "ear.veraison.annotated-evidence", {})
      idc := object.get(ev, "init_data_claims", {})
      raw := object.get(idc, "instance_id", "")
      is_string(raw)
      raw != ""
      inst := lower(raw)
    }

    requester_identity_instance_ids contains inst if {
      cpu0 := object.get(object.get(input, "submods", {}), "cpu0", {})
      idc := object.get(cpu0, "ear.veraison.annotated-evidence.init_data_claims", {})
      raw := object.get(idc, "instance_id", "")
      is_string(raw)
      raw != ""
      inst := lower(raw)
    }

    requester_identity_instance_ids contains inst if {
      cpu0 := object.get(object.get(input, "submods", {}), "cpu0", {})
      ev := object.get(cpu0, "ear.veraison.annotated-evidence", {})
      idc := object.get(ev, "init_data_claims", {})
      identity_toml := object.get(idc, "identity.toml", "")
      is_string(identity_toml)
      some line in split(identity_toml, "\n")
      trimmed := trim(line, " \t\r")
      parts := split(trimmed, "\"")
      count(parts) >= 2
      trim(parts[0], " \t") == "instance_id ="
      raw := parts[1]
      raw != ""
      inst := lower(raw)
    }

    requester_identity_instance_ids_present if {
      count(requester_identity_instance_ids) > 0
    }

    requester_claimed_owner_resource_types contains resource_type if {
      cpu0 := object.get(object.get(input, "submods", {}), "cpu0", {})
      ev := object.get(cpu0, "ear.veraison.annotated-evidence", {})
      idc := object.get(ev, "init_data_claims", {})
      identity := object.get(idc, "identity", {})
      raw := object.get(identity, "owner_resource_type", "")
      is_string(raw)
      raw != ""
      resource_type := lower(raw)
    }

    requester_claimed_owner_resource_types contains resource_type if {
      cpu0 := object.get(object.get(input, "submods", {}), "cpu0", {})
      ev := object.get(cpu0, "ear.veraison.annotated-evidence", {})
      idc := object.get(ev, "init_data_claims", {})
      raw := object.get(idc, "owner_resource_type", "")
      is_string(raw)
      raw != ""
      resource_type := lower(raw)
    }

    requester_claimed_owner_resource_types contains resource_type if {
      cpu0 := object.get(object.get(input, "submods", {}), "cpu0", {})
      idc := object.get(cpu0, "ear.veraison.annotated-evidence.init_data_claims", {})
      raw := object.get(idc, "owner_resource_type", "")
      is_string(raw)
      raw != ""
      resource_type := lower(raw)
    }

    requester_claimed_owner_resource_types contains resource_type if {
      cpu0 := object.get(object.get(input, "submods", {}), "cpu0", {})
      ev := object.get(cpu0, "ear.veraison.annotated-evidence", {})
      idc := object.get(ev, "init_data_claims", {})
      identity_toml := object.get(idc, "identity.toml", "")
      is_string(identity_toml)
      some line in split(identity_toml, "\n")
      trimmed := trim(line, " \t\r")
      parts := split(trimmed, "\"")
      count(parts) >= 2
      trim(parts[0], " \t") == "owner_resource_type ="
      raw := parts[1]
      raw != ""
      resource_type := lower(raw)
    }

    requester_claimed_owner_resource_types_present if {
      count(requester_claimed_owner_resource_types) > 0
    }

    # Identity hash binding for ownership resources -- does NOT chain through legacy fallbacks
    binding_allows_identity_hash(binding) if {
      count(binding.allowed_identity_hashes) > 0
      some hash in requester_identity_hashes
      hash in binding.allowed_identity_hashes
    }

    image_matches_tag_prefix(image, prefix) if {
      startswith(image, prefix)
      contains(image, ":")
      not contains(image, "@sha256:")
    }

    image_is_digest(image) if {
      contains(image, "@sha256:")
    }

    image_is_mutable_tag(image) if {
      contains(image, ":")
      not image_is_digest(image)
    }

    binding_allows_mutable_image_tags(binding) if {
      object.get(binding, "allow_mutable_image_tags", false)
    }

    binding_requires_images(binding) if {
      count(binding.allowed_images) > 0
    }

    binding_requires_images(binding) if {
      count(binding.allowed_image_tag_prefixes) > 0
    }

    binding_matches_images(binding) if {
      requester_images_present
      count(binding.allowed_images) > 0
      some image in requester_images
      image_is_digest(image)
      image in binding.allowed_images
    }

    binding_matches_images(binding) if {
      requester_images_present
      binding_allows_mutable_image_tags(binding)
      count(binding.allowed_images) > 0
      some image in requester_images
      image_is_mutable_tag(image)
      image in binding.allowed_images
    }

    binding_matches_images(binding) if {
      requester_images_present
      binding_allows_mutable_image_tags(binding)
      count(binding.allowed_image_tag_prefixes) > 0
      some image in requester_images
      some prefix in binding.allowed_image_tag_prefixes
      image_is_mutable_tag(image)
      image_matches_tag_prefix(image, prefix)
    }

    binding_requires_init_data(binding) if {
      count(binding.allowed_init_data_hashes) > 0
    }

    binding_matches_init_data(binding) if {
      requester_init_data_present
      count(binding.allowed_init_data_hashes) > 0
      some hash in requester_init_data_hashes
      hash in binding.allowed_init_data_hashes
    }

    binding_allows_attested_identity(binding) if {
      not binding_requires_images(binding)
      not binding_requires_init_data(binding)
    }

    binding_allows_attested_identity(binding) if {
      binding_matches_images(binding)
      not binding_requires_init_data(binding)
    }

    binding_allows_attested_identity(binding) if {
      not binding_requires_images(binding)
      binding_matches_init_data(binding)
    }

    binding_allows_attested_identity(binding) if {
      binding_matches_images(binding)
      binding_matches_init_data(binding)
    }

    binding_allows_namespace(binding) if {
      count(binding.allowed_namespaces) == 0
    }

    binding_allows_namespace(binding) if {
      count(binding.allowed_namespaces) > 0
      requester_namespaces_present
      some ns in requester_namespaces
      ns in binding.allowed_namespaces
    }

    binding_allows_service_account(binding) if {
      count(binding.allowed_service_accounts) == 0
    }

    binding_allows_service_account(binding) if {
      count(binding.allowed_service_accounts) > 0
      requester_service_accounts_present
      some sa in requester_service_accounts
      sa in binding.allowed_service_accounts
    }

    # Trustee only reaches the resource-policy after the caller presents a
    # valid attestation token. Keep the resource decision anchored to the
    # requested resource path and any workload identity claims that are present,
    # but avoid re-deriving attestation success from brittle token field shapes.
    # Legacy path: resource access via attested identity (init_data_hash, image matching)
    allow if {
      binding := requested_binding
      binding_allows_attested_identity(binding)
      binding_allows_namespace(binding)
      binding_allows_service_account(binding)
    }

    # Ownership path: resource access via stable tenant_instance_identity_hash
    # This is an OR alongside legacy -- a resource can be bound by EITHER mechanism.
    allow if {
      binding := requested_binding
      binding_allows_identity_hash(binding)
      binding_allows_namespace(binding)
      binding_allows_service_account(binding)
    }

    binding_allows_owner_resource_tag(binding, tag) if {
      count(binding.allowed_tags) > 0
      tag in binding.allowed_tags
    }

    owner_resource_requested_repository(path_parts) := repository if {
      count(path_parts) == 3
      repository := path_parts[0]
    }

    owner_resource_requested_repository(path_parts) := repository if {
      count(path_parts) == 4
      path_parts[0] == "resource"
      repository := path_parts[1]
    }

    owner_resource_requested_type(path_parts) := resource_type if {
      count(path_parts) == 3
      resource_type := path_parts[1]
    }

    owner_resource_requested_type(path_parts) := resource_type if {
      count(path_parts) == 4
      path_parts[0] == "resource"
      resource_type := path_parts[2]
    }

    owner_resource_requested_tag(path_parts) := tag if {
      count(path_parts) == 3
      tag := path_parts[2]
    }

    owner_resource_requested_tag(path_parts) := tag if {
      count(path_parts) == 4
      path_parts[0] == "resource"
      tag := path_parts[3]
    }

    requested_owner_binding(path_parts) := binding if {
      binding := owner_resource_bindings[owner_resource_requested_type(path_parts)]
      owner_resource_requested_repository(path_parts) == binding.repository
    }

    owner_resource_optional_identity_claims_consistent(namespace, instance, expected_owner_type) if {
      not requester_tenant_ids_present
      not requester_identity_instance_ids_present
      not requester_claimed_owner_resource_types_present
    }

    owner_resource_optional_identity_claims_consistent(namespace, instance, expected_owner_type) if {
      requester_tenant_ids_present
      requester_identity_instance_ids_present
      requester_claimed_owner_resource_types_present
      namespace in requester_tenant_ids
      instance in requester_identity_instance_ids
      expected_owner_type in requester_claimed_owner_resource_types
    }

    owner_resource_claims_consistent(path_parts) if {
      requester_images_present
      requester_namespaces_present
      requester_service_accounts_present
      count(requester_instances) > 0
      count(requester_identity_hashes) > 0
      some namespace in requester_namespaces
      some instance in requester_instances
      expected_owner_type := sprintf("%s-%s-owner", [namespace, instance])
      owner_resource_requested_type(path_parts) == expected_owner_type
      owner_resource_optional_identity_claims_consistent(namespace, instance, expected_owner_type)
    }

    owner_resource_request_allowed(path_parts) if {
      binding := requested_owner_binding(path_parts)
      binding_allows_owner_resource_tag(binding, owner_resource_requested_tag(path_parts))
      binding_allows_identity_hash(binding)
      binding_allows_namespace(binding)
      binding_allows_service_account(binding)
      owner_resource_claims_consistent(path_parts)
    }

    # Generic owner-seed resource READ authorization. Any workload onboarded via
    # deploy-confidential-app.py can read only its own owner resource path once
    # the attested identity claims and pod annotations agree.
    allow if {
      owner_resource_request_allowed(requested_path)
    }

    # ============================================================================
    # Workload-resource CRUD: attestation-authenticated ciphertext writes
    # (Phase 6) — separate from admin-only /resource POST/DELETE
    # ============================================================================

    # Workload-authenticated ciphertext PUT authorization for the caller's own
    # owner resource path. Missing namespace/service-account/instance/identity
    # claims fail closed instead of falling through.
    allow if {
        data.plugin == "workload-resource"
        data.method == "PUT"
        owner_resource_request_allowed(requested_path)
    }

    # Workload-authenticated ciphertext DELETE authorization for the caller's
    # own owner resource path.
    allow if {
        data.plugin == "workload-resource"
        data.method == "DELETE"
        owner_resource_request_allowed(requested_path)
    }

