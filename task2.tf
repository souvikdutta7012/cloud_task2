provider "aws" {
  region = "ap-south-1"
}


resource "tls_private_key" "task2_key" {  
  algorithm = "RSA"
}
module "key_pair" {
  source = "terraform-aws-modules/key-pair/aws"
  key_name   = "task2_key"
  public_key = tls_private_key.task2_key.public_key_openssh
}


resource "aws_vpc" "myvpc" {
  cidr_block = "10.5.0.0/16"
  enable_dns_hostnames = true
  tags = {
    Name = "task2"
  }
}


resource "aws_subnet" "mysubnet" {
  vpc_id            = "${aws_vpc.myvpc.id}"
  availability_zone = "ap-south-1a"
  cidr_block        = "10.5.1.0/24"
  map_public_ip_on_launch = true
  tags = {
    Name = "task2-1a"
  }
}


resource "aws_internet_gateway" "mygateway" {
  vpc_id = "${aws_vpc.myvpc.id}"
  tags = {
    Name = "task2-1a"
  }
}
resource "aws_route_table" "mytable" {
  vpc_id = "${aws_vpc.myvpc.id}"
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "${aws_internet_gateway.mygateway.id}"
  }
  tags = {
    Name = "task2-1a"
  }
}
resource "aws_route_table_association" "myassociation" {
  subnet_id      = aws_subnet.mysubnet.id
  route_table_id = aws_route_table.mytable.id
}

resource "aws_security_group" "allow_http" {
  name        = "allow_http"
  description = "Allow HTTP inbound traffic"
  vpc_id      = "${aws_vpc.myvpc.id}"

  ingress {
    description = "Http from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [ "0.0.0.0/0" ]
  }
  ingress {
    description = "SSH from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [ "0.0.0.0/0" ]
  }
  ingress {
    description = "NFS"
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = [ "0.0.0.0/0" ]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "task2securitygroup"
  }
}



resource "aws_efs_file_system" "mypd" {
  creation_token = "my-secure-pd"
  tags = {
    Name = "MyPersonalFileSystem"
  }
}

resource "aws_efs_file_system_policy" "policy" {
  file_system_id = "${aws_efs_file_system.mypd.id}"
  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Id": "efs-policy-wizard-c45881c9-af16-441d-aa48-0fbd68ffaf79",
    "Statement": [
        {
            "Sid": "efs-statement-20e4223c-ca0e-412d-8490-3c3980f60788",
            "Effect": "Allow",
            "Principal": {
                "AWS": "*"
            },
            "Resource": "${aws_efs_file_system.mypd.arn}",
            "Action": [
                "elasticfilesystem:ClientMount",
                "elasticfilesystem:ClientWrite",
                "elasticfilesystem:ClientRootAccess"
            ],
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "true"
                }
            }
        }
    ]
}
POLICY
}

resource "aws_efs_mount_target" "mytarget" {
  file_system_id = "${aws_efs_file_system.mypd.id}"
  subnet_id      = "${aws_subnet.mysubnet.id}"
  security_groups = [ "${aws_security_group.allow_http.id}" ]
}

resource "aws_instance" "task2web" {
  ami           = "ami-00b494a3f139ba61f"
  instance_type = "t2.micro"
  key_name      = "task2_key"
  availability_zone = "ap-south-1a"
  subnet_id     = "${aws_subnet.mysubnet.id}"
  security_groups = [ "${aws_security_group.allow_http.id}" ]
  tags = {
    Name = "MyWebServer"
  }
}
resource "null_resource" "myattach"  {
  depends_on = [
    aws_efs_mount_target.mytarget,
  ]
  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key =  tls_private_key.task2_key.private_key_pem
    host     = aws_instance.task2web.public_ip
  }
  provisioner "remote-exec" {
    inline = [
      "sleep 30",
      "sudo yum install -y httpd git php amazon-efs-utils nfs-utils",
      "sudo systemctl start httpd",
      "sudo systemctl enable httpd",
      "sudo chmod ugo+rw /etc/fstab",
      "sudo echo '${aws_efs_file_system.mypd.id}:/ /var/www/html efs tls,_netdev' >> /etc/fstab",
      "sudo mount -a -t efs,nfs4 defaults",
      "sudo rm -rf /var/www/html/*",
      "sudo git clone https://github.com/souvikdutta7012/cloud_task2.git /var/www/html/"
    ]
  }
}
resource "aws_s3_bucket" "task2-bucket" {
  bucket = "task2-bucket"
  acl    = "public-read"
  force_destroy  = true
  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["PUT", "POST"]
    allowed_origins = ["https://task2-bucket"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
depends_on = [
   null_resource.myattach,
  ]
}

resource "aws_s3_bucket_object" "task2obj" {
  key = "souvik.png"
  bucket = aws_s3_bucket.task2-bucket.id
  source = "souvik.png"
  acl="public-read"
}


# Create Cloudfront distribution
resource "aws_cloudfront_distribution" "distribution" {
    origin {
        domain_name = "${aws_s3_bucket.task2-bucket.bucket_regional_domain_name}"
        origin_id = "S3-${aws_s3_bucket.task2-bucket.bucket}"

        custom_origin_config {
            http_port = 80
            https_port = 443
            origin_protocol_policy = "match-viewer"
            origin_ssl_protocols = ["TLSv1", "TLSv1.1", "TLSv1.2"]
        }
}
    default_root_object = "souvik.png"
    enabled = true

  
    custom_error_response {
        error_caching_min_ttl = 3000
        error_code = 404
        response_code = 200
        response_page_path = "/souvik.png"
    }

    default_cache_behavior {
        allowed_methods = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
        cached_methods = ["GET", "HEAD"]
        target_origin_id = "S3-${aws_s3_bucket.task2-bucket.bucket}"

        #Not Forward all query strings, cookies and headers
        forwarded_values {
            query_string = false
	    cookies {
		forward = "none"
	    }
            
        }

        viewer_protocol_policy = "redirect-to-https"
        min_ttl = 0
        default_ttl = 3600
        max_ttl = 86400
    }

    # Restricts who is able to access this content
    restrictions {
        geo_restriction {
            # type of restriction, blacklist, whitelist or none
            restriction_type = "none"
        }
    }

    # SSL certificate for the service.
    viewer_certificate {
        cloudfront_default_certificate = true
    }
}
resource "null_resource" "mypic"  {
  depends_on = [
    null_resource.myattach,
    aws_cloudfront_distribution.distribution,
  ]
  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key =  tls_private_key.task2_key.private_key_pem
    host     = aws_instance.task2web.public_ip
  }
  provisioner "remote-exec" {
    inline = [
        "sudo chmod ugo+rw /var/www/html/index.php",
        "sudo echo '<img src=http://${aws_cloudfront_distribution.distribution.domain_name}/souvik.png alt='SOUVIK DUTTA' width='500' height='600'</a>' >> /var/www/html/index.php"
    ]
  }
}

output "cloudfront_ip_addr" {
  value = aws_cloudfront_distribution.distribution.domain_name
}

